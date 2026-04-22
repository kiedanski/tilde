//! Email parsing using mailparse

use anyhow::{Context, Result};

/// A parsed email with extracted metadata.
#[derive(Debug, Clone)]
pub struct ParsedEmail {
    pub message_id: String,
    pub from_address: String,
    pub from_name: Option<String>,
    pub to_addresses: Vec<String>,
    pub cc_addresses: Vec<String>,
    pub subject: String,
    pub date: String,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub body_text: String,
    pub snippet: Option<String>,
    pub has_attachment: bool,
    pub size_bytes: usize,
    pub attachments: Vec<Attachment>,
}

#[derive(Debug, Clone)]
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

impl ParsedEmail {
    /// Parse raw RFC822 email bytes into structured data.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let parsed = mailparse::parse_mail(raw).context("Failed to parse email")?;

        let headers = &parsed.headers;

        let message_id = get_header(headers, "Message-ID")
            .unwrap_or_else(|| format!("<generated-{}>", uuid::Uuid::new_v4()));
        let message_id = message_id
            .trim_matches(|c| c == '<' || c == '>')
            .to_string();

        let from_raw = get_header(headers, "From").unwrap_or_default();
        let (from_name, from_address) = parse_address(&from_raw);

        let to_raw = get_header(headers, "To").unwrap_or_default();
        let to_addresses = parse_address_list(&to_raw);

        let cc_raw = get_header(headers, "Cc").unwrap_or_default();
        let cc_addresses = if cc_raw.is_empty() {
            vec![]
        } else {
            parse_address_list(&cc_raw)
        };

        let subject = get_header(headers, "Subject").unwrap_or_default();

        let date = get_header(headers, "Date").unwrap_or_default();
        let date = parse_date_to_iso(&date);

        let in_reply_to = get_header(headers, "In-Reply-To")
            .map(|s| s.trim_matches(|c| c == '<' || c == '>').to_string())
            .filter(|s| !s.is_empty());

        let references_raw = get_header(headers, "References").unwrap_or_default();
        let references: Vec<String> = references_raw
            .split_whitespace()
            .map(|s| s.trim_matches(|c| c == '<' || c == '>').to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // Extract body text and attachments
        let mut body_text = String::new();
        let mut attachments = Vec::new();
        extract_parts(&parsed, &mut body_text, &mut attachments);

        let snippet = if body_text.is_empty() {
            None
        } else {
            Some(body_text.chars().take(200).collect())
        };

        let has_attachment = !attachments.is_empty();

        Ok(ParsedEmail {
            message_id,
            from_address,
            from_name,
            to_addresses,
            cc_addresses,
            subject,
            date,
            in_reply_to,
            references,
            body_text,
            snippet,
            has_attachment,
            size_bytes: raw.len(),
            attachments,
        })
    }
}

fn get_header(headers: &[mailparse::MailHeader<'_>], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|h| h.get_key().eq_ignore_ascii_case(name))
        .map(|h| h.get_value())
}

fn parse_address(raw: &str) -> (Option<String>, String) {
    let raw = raw.trim();
    if let Some(start) = raw.rfind('<') {
        let name = raw[..start].trim().trim_matches('"').to_string();
        let addr = raw[start..]
            .trim_matches(|c| c == '<' || c == '>')
            .trim()
            .to_string();
        let name = if name.is_empty() { None } else { Some(name) };
        (name, addr)
    } else {
        (None, raw.to_string())
    }
}

fn parse_address_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| {
            let s = s.trim();
            if let Some(start) = s.rfind('<') {
                s[start..]
                    .trim_matches(|c| c == '<' || c == '>')
                    .trim()
                    .to_string()
            } else {
                s.to_string()
            }
        })
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_date_to_iso(date_str: &str) -> String {
    // Try to parse RFC2822 date, fall back to raw string
    if let Ok(ts) = mailparse::dateparse(date_str) {
        // Convert unix timestamp to ISO 8601
        if let Ok(t) = jiff::Timestamp::from_second(ts) {
            return t.strftime("%Y-%m-%dT%H:%M:%SZ").to_string();
        }
    }
    date_str.to_string()
}

fn extract_parts(
    part: &mailparse::ParsedMail<'_>,
    body_text: &mut String,
    attachments: &mut Vec<Attachment>,
) {
    let content_type = part.ctype.mimetype.to_lowercase();
    let disposition = part.get_content_disposition();

    // Check if this is an attachment
    if disposition.disposition == mailparse::DispositionType::Attachment {
        let filename = disposition
            .params
            .get("filename")
            .cloned()
            .unwrap_or_else(|| format!("attachment_{}", attachments.len()));
        if let Ok(data) = part.get_body_raw() {
            attachments.push(Attachment {
                filename,
                content_type: content_type.clone(),
                data,
            });
        }
        return;
    }

    if part.subparts.is_empty() {
        // Leaf node
        if content_type.starts_with("text/plain") && body_text.is_empty() {
            if let Ok(text) = part.get_body() {
                *body_text = text;
            }
        } else if content_type.starts_with("text/html") && body_text.is_empty() {
            // Strip HTML tags for plain text
            if let Ok(html) = part.get_body() {
                *body_text = strip_html(&html);
            }
        }
    } else {
        for sub in &part.subparts {
            extract_parts(sub, body_text, attachments);
        }
    }
}

fn strip_html(html: &str) -> String {
    let mut result = String::new();
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => result.push(c),
            _ => {}
        }
    }
    // Collapse whitespace
    result.split_whitespace().collect::<Vec<_>>().join(" ")
}
