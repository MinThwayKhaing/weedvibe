use actix_web::{web, App, HttpServer};
use sqlx::postgres::PgPoolOptions;
use std::env;

mod user;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    // Create a connection pool
    let db_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create pool.");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(user::AppState {
                db_pool: db_pool.clone(),
            }))
            .configure(user::init)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
