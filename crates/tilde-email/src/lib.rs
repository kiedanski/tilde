//! tilde-email: Email archive via IMAP with Maildir storage

pub mod imap;
pub mod maildir;
pub mod parser;

pub use maildir::{MaildirReader, MaildirWriter};
pub use parser::ParsedEmail;
