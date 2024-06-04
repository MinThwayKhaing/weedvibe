pub mod controller;
pub mod models;

use actix_web::web;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/user").route("/create", web::post().to(controller::create_user)));
}
