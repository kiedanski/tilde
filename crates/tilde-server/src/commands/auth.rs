use tilde_cli::{AppPasswordCommands, AuthCommands};
use tilde_core::{auth, config::Config, db};

pub async fn run_auth(config_path: Option<&str>, command: AuthCommands) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;

    match command {
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
    }
    Ok(())
}
