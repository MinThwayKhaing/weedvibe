use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{prelude::FromRow, PgPool, Row};
#[derive(Deserialize)]
pub struct CreateUser {
    pub username: String,
    pub password: String,
    pub email: String,
}
#[derive(Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub email: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Deserialize)]
pub struct GetUsersQuery {
    pub search: Option<String>,
    pub page: Option<usize>,
    pub per_page: Option<usize>,
}

#[derive(Serialize)]
pub struct UserResponse {
    pub page: i64,
    pub page_size: i64,
    pub total_count: i64,
    pub users: Vec<User>,
}
#[derive(Clone)]
pub struct AppState {
    pub db_pool: PgPool,
}
