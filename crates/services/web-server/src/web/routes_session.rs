use crate::error::Result;
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use lib_core::model::user::{User, UserBmc};
use lib_core::model::ModelManager;
use lib_web::middleware::mw_auth::CtxW;
use serde_json::{json, Value};

/// Protected — requires `mw_ctx_require`. This is what the gateway calls
/// to find out who the current session belongs to.
pub async fn api_session_handler(
	State(mm): State<ModelManager>,
	CtxW(ctx): CtxW,
) -> Result<Json<Value>> {
	let user: User = UserBmc::get(&ctx, &mm, ctx.user_id()).await?;

	Ok(Json(json!({
		"result": {
			"id": user.id,
			"email": user.email,
		}
	})))
}

pub fn routes(mm: ModelManager) -> Router {
	Router::new()
		.route("/api/session", get(api_session_handler))
		.with_state(mm)
}
