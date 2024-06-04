use crate::routes::AppState;
use actix_web::{web, HttpResponse, Responder, ResponseError};
use bcrypt::{verify, BcryptError};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use sqlx::{Error as SqlxError, PgPool};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct Tokens {
    access_token: String,
    refresh_token: String,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] SqlxError),

    #[error("Password hashing error: {0}")]
    PasswordError(#[from] BcryptError),
}

impl ResponseError for AuthError {
    fn error_response(&self) -> HttpResponse {
        match *self {
            AuthError::DatabaseError(_) => {
                HttpResponse::InternalServerError().json("Database error")
            }
            AuthError::PasswordError(_) => {
                HttpResponse::InternalServerError().json("Password error")
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub password: String,
    pub role: String,
    pub verified: Option<bool>,
    pub created_at: DateTime<Utc>,
}

pub async fn authenticate(
    pool: &PgPool,
    email: &str,
    password: &str,
) -> Result<Option<User>, AuthError> {
    log::debug!("Authenticating user with email: {}", email);

    let user = sqlx::query_as!(
        User,
        r#"
        SELECT id, name, email, password, role, verified, created_at
        FROM users
        WHERE email = $1
        "#,
        email
    )
    .fetch_optional(pool)
    .await?;

    // If no user found with the given email, return early
    let user = match user {
        Some(user) => user,
        None => return Ok(None),
    };

    log::debug!("User found: {:?}", user);

    // Verify the password
    let password_matched = verify(password, &user.password)?;

    if password_matched {
        log::debug!("Password matched for user: {}", user.id);
        Ok(Some(user))
    } else {
        log::debug!("Password did not match for user: {}", user.id);
        Ok(None)
    }
}

pub async fn login(
    pool: web::Data<AppState>,
    login_req: web::Json<LoginRequest>,
) -> impl Responder {
    let email = login_req.email.clone();
    let password = login_req.password.clone();

    log::info!("Login attempt for email: {}", email);

    // Validate user credentials
    let user = authenticate(&pool.db_pool, &email, &password).await;
    match user {
        Ok(Some(user)) => {
            log::info!("User authenticated: {}", user.id);

            // Generate JWT tokens
            let access_token = generate_access_token(&user);
            let refresh_token = generate_refresh_token();
            let refresh_token_str = refresh_token.to_string();
            let expiration_time = Utc::now() + Duration::days(30); // 30 days expiration time

            // Save tokens in the database
            if let Err(e) =
                save_refresh_token(&pool.db_pool, &refresh_token, &user.id, &expiration_time).await
            {
                log::error!("Failed to save refresh token: {}", e);
                return e.error_response();
            }
            if let Err(e) = save_auth_token(
                &pool.db_pool,
                &access_token,
                &user.id,
                &(Utc::now() + Duration::hours(1)),
            )
            .await
            {
                log::error!("Failed to save auth token: {}", e);
                return e.error_response();
            }

            // Respond with tokens
            HttpResponse::Ok().json(Tokens {
                access_token,
                refresh_token: refresh_token_str,
            })
        }
        Ok(None) => {
            log::warn!("Unauthorized login attempt for email: {}", email);
            HttpResponse::Unauthorized().finish()
        }
        Err(e) => {
            log::error!("Login error for email {}: {}", email, e);
            e.error_response()
        }
    }
}

fn generate_access_token(user: &User) -> String {
    let expiration_time = Utc::now() + Duration::hours(1); // Token expires in 1 hour
    let claims = Claims {
        sub: user.id.to_string(),
        exp: expiration_time.timestamp() as usize,
    };
    let mut rng = rand::thread_rng();
    let secret_key: String = (0..32)
        .map(|_| rng.sample(Alphanumeric) as char) // Convert u8 to char
        .collect();
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret_key.as_ref()), // Replace with your secret key
    )
    .expect("Token encoding failed")
}

fn generate_refresh_token() -> Uuid {
    Uuid::new_v4()
}

async fn save_refresh_token(
    pool: &PgPool,
    refresh_token: &Uuid,
    user_id: &Uuid,
    expires_at: &chrono::DateTime<Utc>,
) -> Result<(), AuthError> {
    log::debug!("Saving refresh token for user: {}", user_id);
    sqlx::query!(
        r#"
        INSERT INTO refresh_tokens (token, expires_at, user_id)
        VALUES ($1, $2, $3)
        "#,
        refresh_token,
        expires_at,
        user_id
    )
    .execute(pool)
    .await
    .map_err(|e| AuthError::DatabaseError(e.into()))?;
    Ok(())
}

async fn save_auth_token(
    pool: &PgPool,
    access_token: &str,
    user_id: &Uuid,
    expires_at: &chrono::DateTime<Utc>,
) -> Result<(), AuthError> {
    log::debug!("Saving auth token for user: {}", user_id);
    sqlx::query!(
        r#"
        INSERT INTO auth_tokens (token, expires_at, user_id)
        VALUES ($1, $2, $3)
        "#,
        access_token,
        expires_at,
        user_id
    )
    .execute(pool)
    .await
    .map_err(|e| AuthError::DatabaseError(e.into()))?;
    Ok(())
}
