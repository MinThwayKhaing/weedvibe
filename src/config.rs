use dotenv::dotenv;
use std::env;
use tokio_postgres::{Error, NoTls};

pub async fn connect_to_db() -> Result<tokio_postgres::Client, Error> {
    dotenv().ok();
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let (client, connection) = tokio_postgres::connect(&db_url, NoTls).await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });

    Ok(client)
}
