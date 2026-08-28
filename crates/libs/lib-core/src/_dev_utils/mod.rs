// region:    --- Modules

mod dev_db;

use crate::ctx::Ctx;
use crate::model::{self, ModelManager};
use modql::filter::OpValString;
use tokio::sync::OnceCell;
use tracing::info;

// endregion: --- Modules

/// Initialize environment for local development.
/// (for early development, will be called from main()).
pub async fn init_dev() {
	static INIT: OnceCell<()> = OnceCell::const_new();

	INIT.get_or_init(|| async {
		info!("{:<12} - init_dev_all()", "FOR-DEV-ONLY");

		dev_db::init_dev_db().await.unwrap();
	})
	.await;
}

/// Initialize test environment.
pub async fn init_test() -> ModelManager {
	static INIT: OnceCell<ModelManager> = OnceCell::const_new();

	let mm = INIT
		.get_or_init(|| async {
			init_dev().await;
			// NOTE: Rare occasion where unwrap is kind of ok.
			ModelManager::new().await.unwrap()
		})
		.await;

	mm.clone()
}

// region:    --- User seed/clean
//
// NOTE: These seed the local `user` mirror table only. They take an
// already-created SuperTokens `(st_user_id, email)` pair rather than
// calling the core themselves — lib-core intentionally doesn't depend on
// lib-auth/SuperTokens. Tests that need a real signed-up user should call
// `lib_auth::supertokens::sign_up` first and pass the result in here.

pub async fn seed_user(
	ctx: &Ctx,
	mm: &ModelManager,
	st_user_id: &str,
	email: &str,
) -> model::Result<i64> {
	model::user::UserBmc::create(
		ctx,
		mm,
		model::user::UserForCreate {
			st_user_id: st_user_id.to_string(),
			email: email.to_string(),
			last_ip: None,
			last_visitor_id: None,
		},
	)
	.await
}

pub async fn clean_users(
	ctx: &Ctx,
	mm: &ModelManager,
	contains_email: &str,
) -> model::Result<usize> {
	let users = model::user::UserBmc::list(
		ctx,
		mm,
		Some(vec![model::user::UserFilter {
			email: Some(OpValString::Contains(contains_email.to_string()).into()),
			..Default::default()
		}]),
		None,
	)
	.await?;
	let count = users.len();

	for user in users {
		model::user::UserBmc::delete(ctx, mm, user.id).await?;
	}

	Ok(count)
}

// endregion: --- User seed/clean
