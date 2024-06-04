pub mod authcontroller;

use actix_web::web;
use log::info;

pub fn init(cfg: &mut web::ServiceConfig) {
    info!("Initializing util routes");
    cfg.service(web::scope("/auth").route("/login", web::post().to(authcontroller::login)));
}
