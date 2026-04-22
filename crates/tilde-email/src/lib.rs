//! tilde-email: Email archive via IMAP with Maildir storage and FTS5 search

pub mod imap;
pub mod index;
pub mod maildir;
pub mod parser;

pub use index::{
    add_tag, extract_attachments, get_thread, index_email, reindex_from_maildir, remove_tag,
    search_emails,
};
pub use maildir::{MaildirReader, MaildirWriter};
pub use parser::ParsedEmail;
