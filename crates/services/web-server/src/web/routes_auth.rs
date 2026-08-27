use axum::routing::post;
use axum::Router;
use lib_core::model::ModelManager;
use lib_web::handlers::handlers_auth;

pub fn routes(mm: ModelManager) -> Router {
	Router::new()
		.route("/api/signup", post(handlers_auth::api_signup_handler))
		.route("/api/signin", post(handlers_auth::api_signin_handler))
		.route("/api/refresh", post(handlers_auth::api_refresh_handler))
		.route("/api/logoff", post(handlers_auth::api_logoff_handler))
		.with_state(mm)
}
