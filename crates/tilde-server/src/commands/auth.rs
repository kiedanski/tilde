use tilde_cli::{AppPasswordCommands, AuthCommands, SessionCommands, WebauthnCommands};
use tilde_core::{auth, config::Config, db};

pub async fn run_auth(config_path: Option<&str>, command: AuthCommands) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;

    match command {
        AuthCommands::ResetPassword => {
            if let Ok(pw) = std::env::var("TILDE_ADMIN_PASSWORD") {
                auth::store_admin_password(&conn, &pw)?;
                println!("Admin password reset successfully");
            } else {
                println!("Set TILDE_ADMIN_PASSWORD environment variable first");
            }
        }
        AuthCommands::AppPassword { command } => match command {
            AppPasswordCommands::Create { name, scope } => {
                let password = auth::create_app_password(&conn, &name, &scope)?;
                println!("App password created:");
                println!("  Name:     {}", name);
                println!("  Scope:    {}", scope);
                println!("  Password: {}", password);
                println!();
                println!("Save this password now — it cannot be shown again.");
            }
            AppPasswordCommands::List => {
                let mut stmt = conn.prepare(
                    "SELECT id, name, scope_prefix, created_at, last_used_at, revoked FROM app_passwords ORDER BY created_at"
                )?;
                let rows = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, bool>(5)?,
                    ))
                })?;
                println!(
                    "{:<36} {:<20} {:<15} {:<25} Status",
                    "ID", "Name", "Scope", "Created"
                );
                println!("{}", "-".repeat(110));
                for row in rows {
                    let (id, name, scope, created, _last_used, revoked) = row?;
                    let status = if revoked { "revoked" } else { "active" };
                    println!(
                        "{:<36} {:<20} {:<15} {:<25} {}",
                        id, name, scope, created, status
                    );
                }
            }
            AppPasswordCommands::Revoke { id } => {
                conn.execute("UPDATE app_passwords SET revoked = 1 WHERE id = ?1", [&id])?;
                println!("App password {} revoked", id);
            }
        },
        AuthCommands::Session { command } => match command {
            SessionCommands::List => {
                let mut stmt = conn.prepare(
                    "SELECT token_prefix, created_at, last_used_at, expires_at, user_agent, source_ip, revoked FROM auth_sessions ORDER BY created_at DESC"
                )?;
                let rows = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, bool>(6)?,
                    ))
                })?;
                println!(
                    "{:<24} {:<20} {:<16} {:<25} Status",
                    "Prefix", "User Agent", "Source IP", "Last Used"
                );
                println!("{}", "-".repeat(110));
                for row in rows {
                    let (prefix, _created, last_used, _expires, user_agent, source_ip, revoked) =
                        row?;
                    let status = if revoked { "revoked" } else { "active" };
                    let ua = user_agent.unwrap_or_else(|| "-".to_string());
                    let ip = source_ip.unwrap_or_else(|| "-".to_string());
                    println!(
                        "{:<24} {:<20} {:<16} {:<25} {}",
                        prefix, ua, ip, last_used, status
                    );
                }
            }
            SessionCommands::Revoke { id } => {
                conn.execute(
                    "UPDATE auth_sessions SET revoked = 1 WHERE token_prefix = ?1 OR id = ?1",
                    [&id],
                )?;
                println!("Session revoked");
            }
        },
        AuthCommands::Webauthn { command } => match command {
            WebauthnCommands::List => {
                let credentials = auth::list_webauthn_credentials(&conn)?;
                if credentials.is_empty() {
                    println!("No WebAuthn credentials registered");
                } else {
                    println!("{:<38} {:<20} {:<25} Last Used", "ID", "Name", "Created");
                    println!("{}", "-".repeat(110));
                    for (id, name, created_at, last_used_at) in &credentials {
                        let last_used = last_used_at.as_deref().unwrap_or("-");
                        println!("{:<38} {:<20} {:<25} {}", id, name, created_at, last_used);
                    }
                }
            }
            WebauthnCommands::Remove { id } => {
                if auth::remove_webauthn_credential(&conn, &id)? {
                    println!("WebAuthn credential {} removed", id);
                } else {
                    println!("WebAuthn credential {} not found", id);
                }
            }
        },
    }
    Ok(())
}
