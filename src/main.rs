use actix_web::{web, App, HttpServer, HttpResponse, Result, Error, HttpRequest};
use serde::{Deserialize, Serialize};
use std::process::Command;
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use uuid::Uuid;
use chrono::{Utc, Duration};
use actix_web::http::header::{AUTHORIZATION, HeaderValue, WWW_AUTHENTICATE};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,  // 用户标识符
    jti: String,  // Token唯一标识符
    exp: usize,   // 过期时间
}

struct AppState {
    token: String,
}

fn generate_token() -> Result<String, jsonwebtoken::errors::Error> {
    let jti = Uuid::new_v4().to_string();
    let claims = Claims {
        sub: "user".to_owned(),
        jti: jti.clone(),
        exp: (Utc::now() + Duration::days(7)).timestamp() as usize,
    };

    let header = Header::default();
    let key = EncodingKey::from_secret(b"your_secret_key");  // 实际应用中使用环境变量

    encode(&header, &claims, &key)
}

fn verify_token(token: &str) -> Result<(), jsonwebtoken::errors::Error> {
    let token = token.trim_start_matches("Bearer ");
    let secret = b"your_secret_key"; // 实际应用中使用环境变量
    let validation = Validation::default();

    decode::<Claims>(token, &DecodingKey::from_secret(secret), &validation)?;
    Ok(())
}

async fn execute_command(
    req: HttpRequest,
    json: web::Json<CommandRequest>,
    data: web::Data<AppState>
) -> Result<HttpResponse, Error> {
    let headers = req.headers();
    let auth_header = headers.get(AUTHORIZATION)
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Authorization header missing"))?
        .to_str()
        .map_err(|_| actix_web::error::ErrorUnauthorized("Invalid Authorization header format"))?;

    let token = auth_header.trim_start_matches("Bearer ");

    if token != data.token {
        let mut response = HttpResponse::Unauthorized();
        response.insert_header((WWW_AUTHENTICATE, HeaderValue::from_static("Bearer")));
        return Ok(response.json("Invalid token"));
    }

    match verify_token(&token) {
        Ok(_) => {
            let output = Command::new(&json.command)
                .args(&json.args)
                .output()
                .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to execute command: {}", e)))?;

            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();

            Ok(HttpResponse::Ok().json(CommandResponse {
                stdout,
                stderr,
                status: output.status.code()
            }))
        },
        Err(_) => {
            let mut response = HttpResponse::Unauthorized();
            response.insert_header((WWW_AUTHENTICATE, HeaderValue::from_static("Bearer")));
            Ok(response.json("Invalid token"))
        }
    }
}

#[derive(Deserialize)]
struct CommandRequest {
    command: String,
    args: Vec<String>,
}

#[derive(Serialize)]
struct CommandResponse {
    stdout: String,
    stderr: String,
    status: Option<i32>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let token = generate_token().expect("Failed to generate token");
    println!("Generated token: {}", token);

    let app_state = web::Data::new(AppState { token: token.clone() });

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .service(
                web::resource("/execute")
                    .route(web::post().to(execute_command))
            )
    })
    .bind("127.0.0.1:8088")?
    .run()
    .await
}
