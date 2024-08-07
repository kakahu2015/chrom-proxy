use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};
use actix_web::{web, App, HttpServer, HttpResponse, Result, Error, HttpRequest};
use std::process::Command;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use actix_web::http::header::{AUTHORIZATION, HeaderValue, WWW_AUTHENTICATE, HeaderMap};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,  // 用户标识符
    jti: String,  // Token唯一标识符
}

struct TokenStore {
    valid_tokens: Mutex<HashSet<String>>,
}

impl TokenStore {
    fn new() -> Self {
        TokenStore {
            valid_tokens: Mutex::new(HashSet::new()),
        }
    }

    fn add_token(&self, jti: String) {
        self.valid_tokens.lock().unwrap().insert(jti);
    }

    fn is_token_valid(&self, jti: &str) -> bool {
        self.valid_tokens.lock().unwrap().contains(jti)
    }

    fn revoke_token(&self, jti: &str) {
        self.valid_tokens.lock().unwrap().remove(jti);
    }
}

fn generate_token(user_id: &str, store: &TokenStore) -> Result<String, jsonwebtoken::errors::Error> {
    let jti = Uuid::new_v4().to_string();
    let claims = Claims {
        sub: user_id.to_owned(),
        jti: jti.clone(),
    };

    let header = Header::default();
    let key = EncodingKey::from_secret(b"your_secret_key");  // 实际应用中使用环境变量

    let token = encode(&header, &claims, &key)?;
    store.add_token(jti);
    Ok(token)
}

fn verify_token(token: &str, store: &TokenStore) -> Result<String, jsonwebtoken::errors::Error> {
    let token = token.trim_start_matches("Bearer ");
    let secret = b"your_secret_key"; // 实际应用中使用环境变量
    let validation = Validation::default();

    let token_data = decode::<Claims>(token, &DecodingKey::from_secret(secret), &validation)?;
    
    if store.is_token_valid(&token_data.claims.jti) {
        Ok(token_data.claims.sub)
    } else {
        Err(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken))
    }
}

async fn execute_command(
    req: HttpRequest,
    json: web::Json<CommandRequest>,
    store: web::Data<Arc<TokenStore>>
) -> Result<HttpResponse, Error> {
    let headers = req.headers();
    let auth_header = headers.get(AUTHORIZATION)
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Authorization header missing"))?
        .to_str()
        .map_err(|_| actix_web::error::ErrorUnauthorized("Invalid Authorization header format"))?;

    let token = auth_header.trim_start_matches("Bearer ");

    match verify_token(&token, &store) {
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


async fn revoke_token(
    req: web::Json<RevokeTokenRequest>,
    store: web::Data<Arc<TokenStore>>
) -> Result<HttpResponse> {
    store.revoke_token(&req.token_id);
    Ok(HttpResponse::Ok().json("Token revoked"))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let store = Arc::new(TokenStore::new());

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(store.clone()))
            .service(
                web::resource("/execute")
                    .route(web::post().to(execute_command))
            )
            .service(
                web::resource("/revoke")
                    .route(web::post().to(revoke_token))
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
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

#[derive(Deserialize)]
struct RevokeTokenRequest {
    token_id: String,
}
