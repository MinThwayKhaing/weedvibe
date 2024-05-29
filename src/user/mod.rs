mod controller;
mod models;

pub use models::*;

use actix_web::web;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/user")
            .route("/create", web::post().to(controller::create_user))
            .route("/users", web::get().to(controller::select_users)),
    );
}
