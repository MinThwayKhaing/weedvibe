use crate::routes::AppState;
use actix_session::Session;
use actix_web::{web, Error as ActixError, HttpResponse, Responder, ResponseError};
use bcrypt::{verify, BcryptError};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode, errors::Result as JwtResult, Algorithm, DecodingKey, Validation};
use jsonwebtoken::{encode, EncodingKey, Header};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use sqlx::{Error as SqlxError, PgPool};
use std::env;
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

#[derive(Debug, Deserialize)]
struct JwtClaims {
    sub: String,
    exp: usize,
    // include any other claims you're interested in
}
#[derive(Debug, thiserror::Error)]
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

pub async fn validate_token(token: &str) -> Result<(), ActixError> {
    // Verify the access token
    let secret_key = env::var("JWT_SECRET_KEY").expect("JWT_SECRET_KEY must be set");
    let validation = Validation::new(Algorithm::HS256);

    let token_data = match decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret_key.as_ref()),
        &validation,
    ) {
        Ok(data) => data,
        Err(err) => match *err.kind() {
            ErrorKind::InvalidToken => {
                log::warn!("Token is invalid");
                return Err(actix_web::error::ErrorUnauthorized("Token is invalid"));
            }
            ErrorKind::ExpiredSignature => {
                log::warn!("Token has expired");
                return Err(actix_web::error::ErrorUnauthorized("Token has expired"));
            }
            _ => {
                log::warn!("Token error: {:?}", err);
                return Err(actix_web::error::ErrorUnauthorized(
                    "Token validation error",
                ));
            }
        },
    };

    // Extract the expiration time from the token
    let expiration_timestamp = token_data.claims.exp as i64;
    let expiration_time = DateTime::<Utc>::from_utc(
        chrono::NaiveDateTime::from_timestamp(expiration_timestamp, 0),
        Utc,
    );

    // Check if access token has expired
    if Utc::now() > expiration_time {
        log::warn!("Access token has expired");
        return Err(actix_web::error::ErrorUnauthorized(
            "Access token has expired",
        ));
    }

    // Log successful token validation
    log::info!("Token validation successful");
    Ok(())
}

pub async fn login(
    pool: web::Data<AppState>,
    login_req: web::Json<LoginRequest>,
) -> impl Responder {
    let email = login_req.email.clone();
    let password = login_req.password.clone();

    let jwt_expiration_minutes: i64 = env::var("JWT_EXPIRATION_MINUTES")
        .expect("JWT_EXPIRATION_MINUTES must be set")
        .parse()
        .expect("JWT_EXPIRATION_MINUTES must be a number");

    // let refresh_token_expiration_days: i64 = env::var("REFRESH_TOKEN_EXPIRATION_DAYS")
    //     .expect("REFRESH_TOKEN_EXPIRATION_DAYS must be set")
    //     .parse()
    //     .expect("REFRESH_TOKEN_EXPIRATION_DAYS must be a number");

    log::info!("Login attempt for email: {}", email);

    let user = authenticate(&pool.db_pool, &email, &password).await;
    match user {
        Ok(Some(user)) => {
            log::info!("User authenticated: {}", user.id);

            let access_token = generate_access_token(&user, jwt_expiration_minutes);
            let refresh_token = generate_refresh_token();
            let refresh_token_str = refresh_token.to_string();
            // let access_expiration_time = Utc::now() + Duration::minutes(jwt_expiration_minutes);
            // let refresh_expiration_time =
            //     Utc::now() + Duration::days(refresh_token_expiration_days);
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

fn generate_access_token(user: &User, expiration_minutes: i64) -> String {
    let expiration_time = Utc::now() + Duration::minutes(expiration_minutes);
    let claims = Claims {
        sub: user.id.to_string(),
        exp: expiration_time.timestamp() as usize,
    };
    let secret_key = env::var("JWT_SECRET_KEY").expect("JWT_SECRET_KEY must be set");

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret_key.as_ref()),
    )
    .expect("Token encoding failed")
}

fn generate_refresh_token() -> Uuid {
    Uuid::new_v4()
}
