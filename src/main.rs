use std::net::TcpListener;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufStream};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;
use std::fs::File;
use std::io::BufReader;
use std::collections::HashMap;
use base64::{Engine as _, engine::general_purpose, engine::GeneralPurpose};
use reqwest;
use tokio::io::AsyncBufReadExt;

const PROXY_AUTH_HEADER: &str = "Proxy-Authorization";
const EXPECTED_USERNAME: &str = "user";
const EXPECTED_PASSWORD: &str = "password";
const FAKE_SITE: &str = "https://www.google.com";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cert = load_certs("path/to/cert.pem")?;
    let key = load_private_key("path/to/key.pem")?;

    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:8443")?;
    println!("HTTPS 代理服务器正在监听 127.0.0.1:8443");

    loop {
        let (stream, _) = listener.accept()?;
        let acceptor = acceptor.clone();

      tokio::spawn(async move {
      if let Ok(stream) = acceptor.accept(stream).await {
          if let Err(e) = handle_client(stream).await {
              eprintln!("处理客户端时出错: {}", e);
          }
        }
    });
        
    }
}

async fn handle_client(mut stream: tokio_rustls::server::TlsStream<TcpStream>) -> Result<(), Box<dyn std::error::Error>> {
    let (reader, writer) = tokio::io::split(stream);
    let mut buf_reader = tokio::io::BufReader::new(reader);
    
    let mut request_line = String::new();
    buf_reader.read_line(&mut request_line).await?;

    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        let bytes_read = buf_stream.read_line(&mut line).await?;
        if bytes_read == 0 || line == "\r\n" {
            break;
        }
        if let Some((key, value)) = parse_header(&line) {
            headers.insert(key, value);
        }
    }

    if !authenticate(&headers) {
        return send_fake_response(&mut buf_stream).await;
    }

    if method == "CONNECT" {
        handle_connect(target, &mut buf_stream).await?;
    } else {
        handle_regular_request(method, target, version, headers, &mut buf_stream).await?;
    }

    Ok(())
}

async fn send_fake_response(buf_stream: &mut BufStream<tokio_rustls::server::TlsStream<TcpStream>>) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let fake_response = client.get(FAKE_SITE).send().await?;
    let status = fake_response.status();
    let headers = fake_response.headers().clone();
    let body = fake_response.bytes().await?;

    let mut response = format!(
        "HTTP/1.1 {}\r\n",
        status
    );

    for (name, value) in headers.iter() {
        if name != "transfer-encoding" {  // 我们会自己处理 content-length
            response.push_str(&format!("{}: {}\r\n", name, value.to_str().unwrap_or("")));
        }
    }

    response.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    
    buf_stream.write_all(response.as_bytes()).await?;
    buf_stream.write_all(&body).await?;
    buf_stream.flush().await?;

    Ok(())
}

async fn handle_connect(target: &str, buf_stream: &mut BufStream<tokio_rustls::server::TlsStream<TcpStream>>) -> Result<(), Box<dyn std::error::Error>> {
    let mut target_stream = TcpStream::connect(target).await?;
    buf_stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
    buf_stream.flush().await?;

    let (mut reader, mut writer) = buf_stream.get_mut().split();
    let (mut target_reader, mut target_writer) = tokio::io::split(target_stream);

    let client_to_target = tokio::io::copy(&mut reader, &mut target_writer);
    let target_to_client = tokio::io::copy(&mut target_reader, &mut writer);

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
    buf_stream: &mut BufStream<tokio_rustls::server::TlsStream<TcpStream>>
) -> Result<(), Box<dyn std::error::Error>> {
    let mut target_stream = TcpStream::connect(target).await?;
    
    target_stream.write_all(format!("{} {} {}\r\n", method, target, version).as_bytes()).await?;
    for (key, value) in &headers {
        target_stream.write_all(format!("{}: {}\r\n", key, value).as_bytes()).await?;
    }
    target_stream.write_all(b"\r\n").await?;

    if let Some(content_length) = headers.get("Content-Length") {
        let content_length: usize = content_length.parse()?;
        let mut remaining = content_length;
        let mut buffer = [0; 8192];
        while remaining > 0 {
            let to_read = remaining.min(buffer.len());
            let bytes_read = buf_stream.read(&mut buffer[..to_read]).await?;
            if bytes_read == 0 {
                break;
            }
            target_stream.write_all(&buffer[..bytes_read]).await?;
            remaining -= bytes_read;
        }
    }

    tokio::io::copy(&mut target_stream, buf_stream).await?;

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

fn authenticate(headers: &HashMap<String, String>) -> bool {
    if let Some(auth) = headers.get(PROXY_AUTH_HEADER) {
        if auth.starts_with("Basic ") {
            if let Ok(decoded) = general_purpose::STANDARD.decode(&auth[6..]) {
                if let Ok(auth_str) = String::from_utf8(decoded) {
                    let parts: Vec<&str> = auth_str.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        return parts[0] == EXPECTED_USERNAME && parts[1] == EXPECTED_PASSWORD;
                    }
                }
            }
        }
    }
    false
}

fn load_certs(filename: &str) -> std::io::Result<Vec<Certificate>> {
    let certfile = File::open(filename)?;
    let mut reader = BufReader::new(certfile);
    let certs = rustls_pemfile::certs(&mut reader)?;
    Ok(certs.into_iter().map(Certificate).collect())
}

fn load_private_key(filename: &str) -> std::io::Result<PrivateKey> {
    let keyfile = File::open(filename)?;
    let mut reader = BufReader::new(keyfile);
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)?;
    Ok(PrivateKey(keys[0].clone()))
}
