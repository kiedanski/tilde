use tilde_cli::{WebhookCommands, WebhookTokenCommands};
use tilde_core::{auth, config::Config, db};

pub async fn run_webhook(
    config_path: Option<&str>,
    command: WebhookCommands,
) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;

    match command {
        WebhookCommands::Token { command } => match command {
            WebhookTokenCommands::Create { name, scopes } => {
                let token = auth::generate_mcp_token(); // reuse token generator
                let token_hash = auth::hash_token(&token);
                let prefix = &token[..std::cmp::min(17, token.len())];
                let id = uuid::Uuid::new_v4().to_string();
                let now = jiff::Zoned::now()
                    .strftime("%Y-%m-%dT%H:%M:%S%:z")
                    .to_string();

                conn.execute(
                    "INSERT INTO webhook_tokens (id, name, token_hash, token_prefix, scopes, created_at, revoked)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
                    rusqlite::params![id, name, token_hash, prefix, scopes, now],
                )?;

                println!("Webhook token created:");
                println!("  Name:   {}", name);
                println!("  Scopes: {}", scopes);
                println!("  Prefix: {}", prefix);
                println!("  Token:  {}", token);
                println!();
                println!("Webhook URL: POST /api/webhook/{}", prefix);
                println!("Save this token now — it cannot be shown again.");
            }
            WebhookTokenCommands::List => {
                let mut stmt = conn.prepare(
                    "SELECT name, token_prefix, scopes, rate_limit, revoked FROM webhook_tokens ORDER BY created_at"
                )?;
                let rows = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i32>(3)?,
                        row.get::<_, bool>(4)?,
                    ))
                })?;
                println!(
                    "{:<20} {:<20} {:<25} {:<10} Status",
                    "Name", "Prefix", "Scopes", "Rate"
                );
                println!("{}", "-".repeat(85));
                for row in rows {
                    let (name, prefix, scopes, rate, revoked) = row?;
                    let status = if revoked { "revoked" } else { "active" };
                    println!(
                        "{:<20} {:<20} {:<25} {:<10} {}",
                        name, prefix, scopes, rate, status
                    );
                }
            }
            WebhookTokenCommands::Revoke { id } => {
                conn.execute(
                    "UPDATE webhook_tokens SET revoked = 1 WHERE id = ?1 OR name = ?1",
                    [&id],
                )?;
                println!("Webhook token revoked");
            }
        },
    }
    Ok(())
}
