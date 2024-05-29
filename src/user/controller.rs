use super::{
    models::{AppState, CreateUser, User},
    GetUsersQuery, UserResponse,
};
use actix_web::{web, HttpResponse, Responder};
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::Row;

pub async fn create_user(data: web::Data<AppState>, user: web::Json<CreateUser>) -> impl Responder {
    let pool = &data.db_pool;
    let result = sqlx::query!(
        "INSERT INTO users (username, email, role) VALUES ($1, $2, $3)",
        user.username,
        user.email,
        "user"
    )
    .execute(pool)
    .await;

    match result {
        Ok(_) => HttpResponse::Ok().body("User created"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Failed to create user: {}", e)),
    }
}

pub async fn select_users(
    data: web::Data<AppState>,
    query: web::Query<GetUsersQuery>,
) -> impl Responder {
    let pool = &data.db_pool;
    let search_query = match &query.search {
        Some(s) if !s.trim().is_empty() => format!("%{}%", s),
        _ => String::from(""),
    };

    let page = query.page.map(|p| p as i64).unwrap_or(1);
    let per_page = query.per_page.map(|p| p as i64).unwrap_or(10);
    let offset = (page - 1) * per_page;

    let count_query = if search_query.is_empty() {
        "SELECT COUNT(*) FROM users".to_string()
    } else {
        "SELECT COUNT(*) FROM users WHERE username LIKE $1".to_string()
    };

    let total_count: i64 = if search_query.is_empty() {
        match sqlx::query_scalar(&count_query).fetch_one(pool).await {
            Ok(count) => count,
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .body(format!("Failed to retrieve user count: {}", e))
            }
        }
    } else {
        match sqlx::query_scalar(&count_query)
            .bind(&search_query)
            .fetch_one(pool)
            .await
        {
            Ok(count) => count,
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .body(format!("Failed to retrieve user count: {}", e))
            }
        }
    };

    let select_query = if search_query.is_empty() {
        "SELECT id, username, email, role, created_at FROM users ORDER BY id LIMIT $1 OFFSET $2"
    } else {
        "SELECT id, username, email, role, created_at FROM users WHERE username LIKE $1 ORDER BY id LIMIT $2 OFFSET $3"
    };

    let query = if search_query.is_empty() {
        sqlx::query(select_query).bind(per_page).bind(offset)
    } else {
        sqlx::query(select_query)
            .bind(&search_query)
            .bind(per_page)
            .bind(offset)
    };

    let rows = match query.fetch_all(pool).await {
        Ok(rows) => rows,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("Failed to retrieve users: {}", e))
        }
    };

    let users: Result<Vec<User>, sqlx::Error> = rows
        .iter()
        .map(|row| {
            let id: i32 = row.get("id");
            let username: String = row.get("username");
            let email: String = row.get("email");
            let role: String = row.get("role");
            let created_at: NaiveDateTime = match row.try_get("created_at") {
                Ok(timestamp) => timestamp,
                Err(e) => {
                    return Err(e.into());
                }
            };

            Ok(User {
                id,
                username,
                email,
                role,
                created_at: DateTime::<Utc>::from_utc(created_at, Utc),
            })
        })
        .collect();

    match users {
        Ok(users) => {
            let response = UserResponse {
                page,
                page_size: per_page,
                total_count,
                users,
            };
            HttpResponse::Ok().json(response)
        }
        Err(e) => {
            HttpResponse::InternalServerError().body(format!("Failed to retrieve users: {}", e))
        }
    }
}
