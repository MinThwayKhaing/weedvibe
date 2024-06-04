use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use actix_web::web;
use sqlx::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub db_pool: PgPool,
}

pub fn get_db_pool(state: &Arc<Mutex<AppState>>) -> Option<MutexGuard<AppState>> {
    match state.lock() {
        Ok(guard) => Some(guard),
        Err(poisoned) => {
            log::error!("AppState mutex has been poisoned: {:?}", poisoned);
            // Recover the poisoned lock by calling `into_inner` directly
            Some(poisoned.into_inner())
        }
    }
}

pub fn init(cfg: &mut web::ServiceConfig) {
    crate::user::init(cfg);
    crate::util::init(cfg);
}
