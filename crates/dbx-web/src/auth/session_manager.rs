use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub username: String,
    pub exp: u64,
    pub iat: u64,
}

#[derive(Clone)]
pub struct SessionManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl SessionManager {
    pub fn new(secret: String) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
        }
    }

    pub fn generate_token(&self, user_id: Uuid, username: &str, ttl_seconds: u64) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = Claims {
            sub: user_id,
            username: username.to_string(),
            exp: now + ttl_seconds,
            iat: now,
        };

        encode(&Header::default(), &claims, &self.encoding_key).unwrap_or_default()
    }

    pub fn validate_token(&self, token: &str) -> Option<Claims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;

        match decode::<Claims>(token, &self.decoding_key, &validation) {
            Ok(data) => Some(data.claims),
            Err(_) => None,
        }
    }
}
