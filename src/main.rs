use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, AsyncBufReadExt};
use tokio::net::{TcpListener, TcpStream};
use rustls::{Certificate, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;
use std::fs::File;
use std::io::{BufReader as StdBufReader};
use std::collections::HashMap;
use reqwest;
use rustls_pemfile::{certs, pkcs8_private_keys};
use url::Url;

const EXPECTED_USERNAME: &str = "user";
const EXPECTED_PASSWORD: &str = "password";
const FAKE_SITE: &str = "https://www.google.com";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cert = load_certs("/app/ssl.crt")?;
    let key = load_private_key("/app/ssl.key")?;

    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("0.0.0.0:443").await?;
    println!("HTTPS proxy server listening on 0.0.0.0:443");

    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            if let Ok(stream) = acceptor.accept(stream).await {
                if let Err(e) = handle_client(stream).await {
                    eprintln!("Error handling client: {}", e);
                }
            }
        });
    }
}

async fn handle_client(stream: tokio_rustls::server::TlsStream<TcpStream>) -> Result<(), Box<dyn std::error::Error>> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut buf_reader = BufReader::new(reader);
    
    let mut request_line = String::new();
    buf_reader.read_line(&mut request_line).await?;

    let (method, target, version) = parse_request_line(&request_line)?;

    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        let bytes_read = buf_reader.read_line(&mut line).await?;
        if bytes_read == 0 || line == "\r\n" {
            break;
        }
        if let Some((key, value)) = parse_header(&line) {
            headers.insert(key, value);
        }
    }

    if !authenticate_from_url(target) {
        return send_fake_response(&mut writer).await;
    }

    if method == "CONNECT" {
        handle_connect(target, &mut buf_reader, &mut writer).await?;
    } else {
        handle_regular_request(method, target, version, headers, &mut buf_reader, &mut writer).await?;
    }

    Ok(())
}

fn authenticate_from_url(target: &str) -> bool {
    if let Ok(url) = Url::parse(target) {
        if let Some(auth) = url.password() {
            return url.username() == EXPECTED_USERNAME && auth == EXPECTED_PASSWORD;
        }
    }
    false
}

async fn send_fake_response(writer: &mut tokio::io::WriteHalf<tokio_rustls::server::TlsStream<TcpStream>>) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let fake_response = client.get(FAKE_SITE).send().await?;
    let status = fake_response.status();
    let headers = fake_response.headers().clone();
    let body = fake_response.bytes().await?;

    let mut response = format!("HTTP/1.1 {}\r\n", status);
    for (name, value) in headers.iter() {
        if name != "transfer-encoding" {
            response.push_str(&format!("{}: {}\r\n", name, value.to_str().unwrap_or("")));
        }
    }
    response.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    
    writer.write_all(response.as_bytes()).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;

    Ok(())
}

async fn handle_connect(
    target: &str,
    reader: &mut BufReader<tokio::io::ReadHalf<tokio_rustls::server::TlsStream<TcpStream>>>,
    writer: &mut tokio::io::WriteHalf<tokio_rustls::server::TlsStream<TcpStream>>
) -> Result<(), Box<dyn std::error::Error>> {
    let mut target_stream = TcpStream::connect(target).await?;
    writer.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
    writer.flush().await?;

    let (mut target_reader, mut target_writer) = target_stream.split();

    let client_to_target = tokio::io::copy(reader, &mut target_writer);
    let target_to_client = tokio::io::copy(&mut target_reader, writer);

    tokio::select! {
        _ = client_to_target => {},
        _ = target_to_client => {},
    }

    Ok(())
}

async fn handle_regular_request(
    method: &str, 
    target: &str, 
    version: &str, 
    headers: HashMap<String, String>, 
    reader: &mut BufReader<tokio::io::ReadHalf<tokio_rustls::server::TlsStream<TcpStream>>>,
    writer: &mut tokio::io::WriteHalf<tokio_rustls::server::TlsStream<TcpStream>>
) -> Result<(), Box<dyn std::error::Error>> {
    let mut target_stream = TcpStream::connect(target).await?;
    
    let mut request = format!("{} {} {}\r\n", method, target, version);
    for (key, value) in &headers {
        request.push_str(&format!("{}: {}\r\n", key, value));
    }
    request.push_str("\r\n");

    target_stream.write_all(request.as_bytes()).await?;

    if let Some(content_length) = headers.get("Content-Length") {
        let content_length: usize = content_length.parse()?;
        let mut remaining = content_length;
        let mut buffer = [0; 8192];
        while remaining > 0 {
            let to_read = remaining.min(buffer.len());
            let bytes_read = reader.read(&mut buffer[..to_read]).await?;
            if bytes_read == 0 {
                break;
            }
            target_stream.write_all(&buffer[..bytes_read]).await?;
            remaining -= bytes_read;
        }
    }

    tokio::io::copy(&mut target_stream, writer).await?;

    Ok(())
}

fn parse_request_line(line: &str) -> Result<(&str, &str, &str), Box<dyn std::error::Error>> {
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or("Missing method")?;
    let target = parts.next().ok_or("Missing target")?;
    let version = parts.next().ok_or("Missing HTTP version")?;
    Ok((method, target, version))
}

fn parse_header(line: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = line.splitn(2, ':').collect();
    if parts.len() == 2 {
        Some((parts[0].trim().to_string(), parts[1].trim().to_string()))
    } else {
        None
    }
}

fn load_certs(filename: &str) -> std::io::Result<Vec<Certificate>> {
    let mut reader = StdBufReader::new(File::open(filename)?);
    certs(&mut reader)
        .map(|certs| certs.into_iter().map(Certificate).collect())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid cert"))
}

fn load_private_key(filename: &str) -> std::io::Result<PrivateKey> {
    let keyfile = File::open(filename)?;
    let mut reader = StdBufReader::new(keyfile);
    
    // 首先尝试原来的方法
    if let Ok(mut keys) = pkcs8_private_keys(&mut reader) {
        if !keys.is_empty() {
            return Ok(PrivateKey(keys.remove(0)));
        }
    }
    
    // 如果失败,尝试读取为 PEM 编码的 EC 密钥
    reader.seek(std::io::SeekFrom::Start(0))?;
    if let Ok(mut keys) = ec_private_keys(&mut reader) {
        if !keys.is_empty() {
            return Ok(PrivateKey(keys.remove(0)));
        }
    }
    
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "No supported private key found in the file",
    ))
}
