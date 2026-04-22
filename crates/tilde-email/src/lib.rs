//! tilde-email: Email archive via IMAP with Maildir storage and FTS5 search

pub mod maildir;
pub mod parser;
pub mod index;
pub mod imap;

pub use index::{index_email, reindex_from_maildir, search_emails, get_thread, add_tag, remove_tag, extract_attachments};
pub use maildir::{MaildirWriter, MaildirReader};
pub use parser::ParsedEmail;
