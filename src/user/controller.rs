use crate::{routes::AppState, user::models::User, util::authcontroller::validate_token};

use super::models::CreateUser;
use crate::util::authcontroller::AuthError;
use actix_session::Session;
use actix_web::{web, HttpRequest, HttpResponse, Responder, ResponseError};

use bcrypt::{hash, DEFAULT_COST};

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}
pub async fn create_user(
    data: web::Data<AppState>,
    req: HttpRequest,
    user: web::Json<CreateUser>,
) -> impl Responder {
    let pool = &data.db_pool;

    // Retrieve and validate Authorization header
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|val| val.to_str().ok())
        .unwrap_or("");

    if !auth_header.starts_with("Bearer ") {
        log::warn!("No Bearer token found in Authorization header");
        return HttpResponse::Unauthorized().body("No Bearer token");
    }

    // Extract the token from Authorization header
    let token = &auth_header[7..];

    // Validate the token
    if validate_token(token).await.is_err() {
        log::warn!("Invalid token");
        return HttpResponse::Unauthorized().body("Invalid token");
    }

    // Hash the user's password
    let hashed_password = match hash(&user.password, DEFAULT_COST) {
        Ok(hp) => hp,
        Err(e) => return AuthError::PasswordError(e).error_response(),
    };

    // Insert user into the database
    let result = sqlx::query!(
        "INSERT INTO users (name, email, password, photo, verified, role) VALUES ($1, $2, $3, $4, $5, $6)",
        user.name,
        user.email,
        hashed_password,
        user.photo.as_deref().unwrap_or("default.png"),
        false,
        "user"
    )
    .execute(pool)
    .await;

    // Handle database operation result
    match result {
        Ok(_) => {
            log::info!("User created successfully");
            HttpResponse::Ok().body("User created")
        }
        Err(e) => {
            log::error!("Failed to create user: {}", e);
            HttpResponse::InternalServerError().body(format!("Failed to create user: {}", e))
        }
    }
}

pub async fn get_user(data: web::Data<AppState>, email: web::Path<String>) -> impl Responder {
    let pool: &PgPool = &data.db_pool;

    let result = sqlx::query_as!(
        User,
        "SELECT id, name,role,email,password,verified ,created_at FROM users WHERE email = $1",
        email.into_inner()
    )
    .fetch_one(pool)
    .await;

    match result {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(e) => HttpResponse::InternalServerError().body(format!("Failed to fetch user: {}", e)),
    }
}
