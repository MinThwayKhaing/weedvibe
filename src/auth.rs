use chrono::{Duration, Utc};
use jsonwebtoken::{
    decode, encode, errors::Result as JwtResult, Algorithm, DecodingKey, EncodingKey, Header,
    Validation,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: Uuid,
    exp: usize,
}

impl Claims {
    fn new(user_id: Uuid, expiration: usize) -> Self {
        Claims {
            sub: user_id,
            exp: expiration,
        }
    }
}

pub fn create_jwt(user_id: Uuid, secret: &[u8], expiration_minutes: i64) -> JwtResult<String> {
    let expiration = Utc::now() + Duration::minutes(expiration_minutes);
    let claims = Claims::new(user_id, expiration.timestamp() as usize);
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
}

pub fn decode_jwt(token: &str, secret: &[u8]) -> JwtResult<Claims> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret),
        &Validation::new(Algorithm::HS256),
    )
    .map(|data| data.claims)
}
