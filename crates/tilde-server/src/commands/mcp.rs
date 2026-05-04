use tilde_cli::{McpCommands, TokenCommands};
use tilde_core::{auth, config::Config, db};

pub async fn run_mcp(config_path: Option<&str>, command: McpCommands) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;

    match command {
        McpCommands::Token { command } => match command {
            TokenCommands::Create { name, scopes } => {
                let token =
                    auth::create_mcp_token(&conn, &name, &scopes, config.mcp.default_rate_limit)?;
                println!("MCP token created:");
                println!("  Name:   {}", name);
                println!("  Scopes: {}", scopes);
                println!("  Token:  {}", token);
                println!();
                println!("Save this token now — it cannot be shown again.");
            }
            TokenCommands::List => {
                let mut stmt = conn.prepare(
                    "SELECT name, token_prefix, scopes, rate_limit, revoked FROM mcp_tokens ORDER BY created_at"
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
                    "{:<20} {:<20} {:<20} {:<15} Status",
                    "Name", "Prefix", "Scopes", "Rate Limit"
                );
                println!("{}", "-".repeat(90));
                for row in rows {
                    let (name, prefix, scopes, rate_limit, revoked) = row?;
                    let status = if revoked { "revoked" } else { "active" };
                    println!(
                        "{:<20} {:<20} {:<20} {:<15} {}",
                        name, prefix, scopes, rate_limit, status
                    );
                }
            }
            TokenCommands::Revoke { id } => {
                conn.execute(
                    "UPDATE mcp_tokens SET revoked = 1 WHERE id = ?1 OR name = ?1",
                    [&id],
                )?;
                println!("MCP token revoked");
            }
            TokenCommands::Rotate { id } => {
                let (name, scopes, rate_limit): (String, String, u32) = conn.query_row(
                    "SELECT name, scopes, rate_limit FROM mcp_tokens WHERE id = ?1 OR name = ?1",
                    [&id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )?;
                conn.execute(
                    "UPDATE mcp_tokens SET revoked = 1 WHERE id = ?1 OR name = ?1",
                    [&id],
                )?;
                let token = auth::create_mcp_token(&conn, &name, &scopes, rate_limit)?;
                println!("MCP token rotated:");
                println!("  Name:   {}", name);
                println!("  Token:  {}", token);
                println!();
                println!("Save this token now — it cannot be shown again.");
            }
        },
        McpCommands::Audit { since, tool, token } => {
            let mut sql = String::from(
                "SELECT token_name, tool_name, duration_ms, created_at FROM mcp_audit_log WHERE 1=1",
            );
            let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
            let mut param_idx = 1;
            if since.is_some() {
                sql.push_str(&format!(" AND created_at >= ?{}", param_idx));
                param_idx += 1;
                params.push(Box::new(since.clone().unwrap()));
            }
            if tool.is_some() {
                sql.push_str(&format!(" AND tool_name = ?{}", param_idx));
                param_idx += 1;
                params.push(Box::new(tool.clone().unwrap()));
            }
            if token.is_some() {
                sql.push_str(&format!(" AND token_name = ?{}", param_idx));
                #[allow(unused_assignments)]
                {
                    param_idx += 1;
                }
                params.push(Box::new(token.clone().unwrap()));
            }
            sql.push_str(" ORDER BY created_at DESC LIMIT 50");

            let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                params.iter().map(|p| p.as_ref()).collect();
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(param_refs.as_slice(), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;

            println!(
                "{:<15} {:<25} {:<8} {:<20}",
                "Token", "Tool", "Duration", "Time"
            );
            println!("{}", "-".repeat(70));
            for row in rows {
                let (token_name, tool_name, duration, time) = row?;
                println!(
                    "{:<15} {:<25} {:<8} {:<20}",
                    token_name,
                    tool_name,
                    format!("{}ms", duration),
                    time
                );
            }
        }
    }
    Ok(())
}
