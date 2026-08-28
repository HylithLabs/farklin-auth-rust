use crate::ctx::Ctx;
use crate::model::base::{self, DbBmc};
use crate::model::modql_utils::time_to_sea_value;
use crate::model::ModelManager;
use crate::model::{Error, Result};
use modql::field::{Fields, HasSeaFields};
use modql::filter::{
	FilterNodes, ListOptions, OpValsInt64, OpValsString, OpValsValue,
};
use sea_query::{Expr, Iden, PostgresQueryBuilder, Query};
use sea_query_binder::SqlxBinder;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::FromRow;

// region:    --- User Types
//
// `user` is a local mirror of the identity SuperTokens core owns. It never
// stores a password or a session token — those live in SuperTokens (see
// `lib_auth::supertokens`). It exists so the rest of the app (and other
// Farklin services, eventually) can join on a stable internal id and keep
// app-specific profile fields (display name, etc.) that SuperTokens has no
// reason to know about.

#[derive(Clone, Debug, sqlx::Type, derive_more::Display, Deserialize, Serialize)]
#[sqlx(type_name = "user_typ")]
pub enum UserTyp {
	Sys,
	User,
}
impl From<UserTyp> for sea_query::Value {
	fn from(val: UserTyp) -> Self {
		val.to_string().into()
	}
}

#[derive(Clone, Fields, FromRow, Debug, Serialize)]
pub struct User {
	pub id: i64,
	pub st_user_id: String,
	pub email: String,
	pub typ: UserTyp,
}

#[derive(Deserialize)]
pub struct UserForCreate {
	pub st_user_id: String,
	pub email: String,
	/// Recorded as the login-risk baseline immediately — nothing to
	/// compare a first-ever login against, but the *next* one needs a
	/// starting point.
	pub last_ip: Option<String>,
	pub last_visitor_id: Option<String>,
}

#[derive(Fields)]
pub struct UserForInsert {
	pub st_user_id: String,
	pub email: String,
	pub last_ip: Option<String>,
	pub last_visitor_id: Option<String>,
}

/// What the session-verify middleware needs to build a `Ctx` from a
/// SuperTokens `userId`, plus the login-risk baseline (see
/// `lib_auth::risk`) the signin handler compares the current attempt
/// against.
#[derive(Clone, FromRow, Fields, Debug)]
pub struct UserForAuth {
	pub id: i64,
	pub st_user_id: String,
	pub email: String,
	pub last_ip: Option<String>,
	pub last_visitor_id: Option<String>,
}

/// Partial update — only `Some` fields are written. Used after a signin
/// that wasn't blocked, to move the risk baseline forward.
#[derive(Fields, Default)]
pub struct UserForFingerprintUpdate {
	pub last_ip: Option<String>,
	pub last_visitor_id: Option<String>,
}

/// Marker trait
pub trait UserBy: HasSeaFields + for<'r> FromRow<'r, PgRow> + Unpin + Send {}

impl UserBy for User {}
impl UserBy for UserForAuth {}

// Note: Since the entity properties Iden will be given by modql
//       UserIden does not have to be exhaustive, but just have the columns
//       we use in our specific code.
#[derive(Iden)]
enum UserIden {
	Id,
	StUserId,
}

#[derive(FilterNodes, Deserialize, Default, Debug)]
pub struct UserFilter {
	pub id: Option<OpValsInt64>,

	pub st_user_id: Option<OpValsString>,
	pub email: Option<OpValsString>,

	pub cid: Option<OpValsInt64>,
	#[modql(to_sea_value_fn = "time_to_sea_value")]
	pub ctime: Option<OpValsValue>,
	pub mid: Option<OpValsInt64>,
	#[modql(to_sea_value_fn = "time_to_sea_value")]
	pub mtime: Option<OpValsValue>,
}

// endregion: --- User Types

// region:    --- UserBmc

pub struct UserBmc;

impl DbBmc for UserBmc {
	const TABLE: &'static str = "user";
}

impl UserBmc {
	/// Mirror a SuperTokens user locally. Called once, right after a
	/// successful `supertokens::sign_up`.
	pub async fn create(
		ctx: &Ctx,
		mm: &ModelManager,
		user_c: UserForCreate,
	) -> Result<i64> {
		let UserForCreate { st_user_id, email, last_ip, last_visitor_id } = user_c;

		let user_fi = UserForInsert {
			st_user_id,
			email: email.clone(),
			last_ip,
			last_visitor_id,
		};

		let user_id = base::create::<Self, _>(ctx, mm, user_fi).await.map_err(
			|model_error| {
				Error::resolve_unique_violation(
					model_error,
					Some(|table: &str, constraint: &str| {
						if table == "user" && constraint.contains("email") {
							Some(Error::UserAlreadyExists { email: email.clone() })
						} else {
							None // Error::UniqueViolation will be created by resolve_unique_violation
						}
					}),
				)
			},
		)?;

		Ok(user_id)
	}

	pub async fn get<E>(ctx: &Ctx, mm: &ModelManager, id: i64) -> Result<E>
	where
		E: UserBy,
	{
		base::get::<Self, _>(ctx, mm, id).await
	}

	/// Looks up the local mirror row by the SuperTokens `userId`. Used by
	/// the session-verify middleware once the core has confirmed the
	/// access token is valid.
	pub async fn first_by_st_user_id<E>(
		_ctx: &Ctx,
		mm: &ModelManager,
		st_user_id: &str,
	) -> Result<Option<E>>
	where
		E: UserBy,
	{
		// -- Build query
		let mut query = Query::select();
		query
			.from(Self::table_ref())
			.columns(E::sea_idens())
			.and_where(Expr::col(UserIden::StUserId).eq(st_user_id));

		// -- Execute query
		let (sql, values) = query.build_sqlx(PostgresQueryBuilder);

		let sqlx_query = sqlx::query_as_with::<_, E, _>(&sql, values);
		let entity = mm.dbx().fetch_optional(sqlx_query).await?;

		Ok(entity)
	}

	pub async fn list(
		ctx: &Ctx,
		mm: &ModelManager,
		filter: Option<Vec<UserFilter>>,
		list_options: Option<ListOptions>,
	) -> Result<Vec<User>> {
		base::list::<Self, _, _>(ctx, mm, filter, list_options).await
	}

	/// Moves the login-risk baseline forward after a signin that wasn't
	/// blocked. Deliberately separate from a generic `update` — callers
	/// must never call this after a `Block` verdict (that would let a
	/// caller with a stolen session cookie overwrite the known-good
	/// baseline with its own fingerprint).
	pub async fn update_login_fingerprint(
		ctx: &Ctx,
		mm: &ModelManager,
		id: i64,
		last_ip: Option<String>,
		last_visitor_id: Option<String>,
	) -> Result<()> {
		base::update::<Self, _>(
			ctx,
			mm,
			id,
			UserForFingerprintUpdate { last_ip, last_visitor_id },
		)
		.await
	}

	/// TODO: For User, deletion will require a soft-delete approach:
	///       - Set `deleted: true`.
	///       - Change `email` to "DELETED-_user_id_@farklin.invalid".
	///       - Clear any other PII (Personally Identifiable Information).
	///       - Also revoke the user in SuperTokens (not this Bmc's job —
	///         caller must also call `supertokens::revoke_all_sessions_for_user`
	///         and the core's user-delete API).
	pub async fn delete(ctx: &Ctx, mm: &ModelManager, id: i64) -> Result<()> {
		base::delete::<Self>(ctx, mm, id).await
	}
}

// endregion: --- UserBmc
