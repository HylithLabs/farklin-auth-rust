use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::info;

type Db = Pool<Postgres>;

// NOTE: Hardcode to prevent deployed system db update. Matches the
//       farklin/farklin_auth db+user docker-compose.dev.yml provisions at
//       container init — there is no separate root superuser to recreate
//       it from, so schema reset (00-recreate-db.sql) runs against this
//       same connection instead of dropping/recreating the database.
const PG_DEV_APP_URL: &str = "postgres://farklin:farklin@localhost:5432/farklin_auth";

// sql files
const SQL_DIR: &str = "sql/dev_initial";

pub async fn init_dev_db() -> Result<(), Box<dyn std::error::Error>> {
	info!("{:<12} - init_dev_db()", "FOR-DEV-ONLY");

	// -- Get the sql_dir
	// Note: This is because cargo test and cargo run won't give the same
	//       current_dir given the worspace layout.
	let current_dir = std::env::current_dir().unwrap();
	let v: Vec<_> = current_dir.components().collect();
	let path_comp = v.get(v.len().wrapping_sub(3));
	let base_dir = if Some(true) == path_comp.map(|c| c.as_os_str() == "crates") {
		v[..v.len() - 3].iter().collect::<PathBuf>()
	} else {
		current_dir.clone()
	};
	let sql_dir = base_dir.join(SQL_DIR);

	// -- Get sql files.
	let mut paths: Vec<PathBuf> = fs::read_dir(sql_dir)?
		.filter_map(|entry| entry.ok().map(|e| e.path()))
		.collect();
	paths.sort();

	// -- SQL Execute each file (00-recreate-db.sql resets schema objects
	//    in-place; the db/role themselves are already owned by
	//    docker-compose.dev.yml's postgres service).
	let app_db = new_db_pool(PG_DEV_APP_URL).await?;

	for path in paths {
		let path_str = path.to_string_lossy();

		if path_str.ends_with(".sql") {
			pexec(&app_db, &path).await?;
		}
	}

	Ok(())
}

async fn pexec(db: &Db, file: &Path) -> Result<(), sqlx::Error> {
	info!("{:<12} - pexec: {file:?}", "FOR-DEV-ONLY");

	// -- Read the file.
	let content = fs::read_to_string(file)?;

	// FIXME: Make the split more sql proof.
	let sqls: Vec<&str> = content.split(';').collect();

	for sql in sqls {
		sqlx::query(sql).execute(db).await.map_err(|e| {
			println!("pexec error while running:\n{sql}");
			println!("cause:\n{e}");
			e
		})?;
	}

	Ok(())
}

async fn new_db_pool(db_con_url: &str) -> Result<Db, sqlx::Error> {
	PgPoolOptions::new()
		.max_connections(1)
		.acquire_timeout(Duration::from_millis(500))
		.connect(db_con_url)
		.await
}
