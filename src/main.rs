use actix_session::SessionMiddleware;
use actix_web::{web, App, HttpServer};
use dotenv::dotenv;
use env_logger::Env;
use log::{error, info};
use sqlx::postgres::PgPoolOptions;
use std::env;
mod routes;
mod user;
mod util;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init(); // Set log level to debug

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    info!("Connecting to the database at {}", database_url);

    // Create a connection pool
    let db_pool = match PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
    {
        Ok(pool) => pool,
        Err(err) => {
            error!("Failed to connect to the database: {}", err);
            std::process::exit(1);
        }
    };
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(routes::AppState {
                db_pool: db_pool.clone(),
            }))
            .configure(routes::init)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
