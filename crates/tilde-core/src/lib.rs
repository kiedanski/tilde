//! tilde-core: config, auth, database, migrations, error types

pub mod auth;
pub mod config;
pub mod db;
pub mod error;

pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;
