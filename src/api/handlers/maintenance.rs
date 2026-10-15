//! Operator endpoints for maintenance window CRUD.
//!
//! Standard `ApiError` envelope. Mounted under `/api/v1/maintenance` so the
//! app's own auth boundary applies. The public surface reads maintenance
//! through `PublicSource::maintenance`, never through this handler.

use crate::request::json::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::AppendHeaders;
use serde::Deserialize;
use utoipa::IntoParams;
use uuid::Uuid;

use crate::app::AppState;
use crate::domain::{
    MaintenanceFilter, MaintenanceUpdate, MaintenanceWindow, MaintenanceWindowUpdate,
    NewMaintenanceUpdate, NewMaintenanceWindow,
};
use crate::error::ApiError;
use crate::error::codes;
use crate::error::{AppError, Result};
use crate::pagination::page::{PageEnvelope, PageOfMaintenanceWindow};
use crate::request::{
    Authorized, CurrentUser, MaintenanceDelete, MaintenanceRead, MaintenanceWrite, RequestSource,
};
use crate::storage::MaintenanceListQuery;

const LIST_LIMIT_DEFAULT: u32 = 50;
const LIST_LIMIT_MAX: u32 = 200;

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListQuery {
    /// Filter: active | upcoming | past | all (default: all). `past` is windows
    /// that ended or were cancelled; `all` includes cancelled windows.
    #[serde(default)]
    pub status: Option<MaintenanceFilter>,
    /// Page size (default 50, max 200).
    pub limit: Option<u32>,
    /// Page offset.
    pub offset: Option<u32>,
}

#[utoipa::path(
    post,
    path = "/api/v1/maintenance",
    tag = "maintenance",
    summary = "Schedule a maintenance window",
    request_body(content = NewMaintenanceWindow, example = json!({
        "title": "Database upgrade",
        "description": "Brief read-only window during PG13 → PG16 migration.",
        "starts_at": "2026-05-14T22:00:00Z",
        "ends_at":   "2026-05-14T23:00:00Z",
        "component_ids": ["01a7b1ce-0000-7000-8000-000000000001"]
    })),
    responses(
        (status = 201, body = MaintenanceWindow,
            headers(("Location" = String, description = "URL of the new maintenance window"))),
        (status = 400, body = ApiError,
            description = "Validation error: ends_at <= starts_at, ends_at not in the future, \
                           unknown component ids, title empty/too long, window longer than the \
                           configured limit"),
    ),
)]
pub async fn create_maintenance(
    State(state): State<AppState>,
    Authorized(org, _): Authorized<MaintenanceWrite>,
    CurrentUser(actor): CurrentUser,
    RequestSource(source): RequestSource,
    Json(new): Json<NewMaintenanceWindow>,
) -> Result<(
    StatusCode,
    AppendHeaders<[(axum::http::HeaderName, HeaderValue); 1]>,
    Json<MaintenanceWindow>,
)> {
    let mw = state
        .maintenance_ops()
        .create(org, new, source, Some(actor))
        .await?;
    let location =
        HeaderValue::from_str(&format!("/api/v1/maintenance/{}", mw.id)).expect("uuid ascii");
    Ok((
        StatusCode::CREATED,
        AppendHeaders([(header::LOCATION, location)]),
        Json(mw),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/maintenance",
    tag = "maintenance",
    summary = "List maintenance windows",
    params(ListQuery),
    responses(
        (status = 200, body = PageOfMaintenanceWindow),
    ),
)]
pub async fn list_maintenance(
    State(state): State<AppState>,
    Authorized(org, _): Authorized<MaintenanceRead>,
    Query(q): Query<ListQuery>,
) -> Result<Json<PageEnvelope<MaintenanceWindow>>> {
    let limit = q
        .limit
        .unwrap_or(LIST_LIMIT_DEFAULT)
        .clamp(1, LIST_LIMIT_MAX);
    let offset = q.offset.unwrap_or(0);
    let filter = q.status.unwrap_or_default();
    let peek = state
        .maintenance_store
        .list(
            org,
            MaintenanceListQuery {
                filter,
                limit: limit + 1,
                offset,
            },
        )
        .await?;
    Ok(Json(PageEnvelope::from_peek(peek, limit, offset)))
}

#[utoipa::path(
    get,
    path = "/api/v1/maintenance/{id}",
    tag = "maintenance",
    summary = "Get a maintenance window",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, body = MaintenanceWindow),
        (status = 404, body = ApiError),
    ),
)]
pub async fn get_maintenance(
    State(state): State<AppState>,
    Authorized(org, _): Authorized<MaintenanceRead>,
    Path(id): Path<Uuid>,
) -> Result<Json<MaintenanceWindow>> {
    match state.maintenance_store.get(org, id).await? {
        Some(mw) => Ok(Json(mw)),
        None => Err(AppError::not_found(
            codes::MAINTENANCE_NOT_FOUND,
            "maintenance window not found",
        )),
    }
}

#[utoipa::path(
    patch,
    path = "/api/v1/maintenance/{id}",
    tag = "maintenance",
    summary = "Edit a maintenance window",
    description = "Editing a window whose `ends_at` is already in the past, or that was cancelled, \
                   is rejected with 422. `ends_at` must stay in the future, except on a running \
                   window: there, an `ends_at` at or before the current time, with `starts_at` \
                   unchanged, ends the window now at the server's clock. A body that sets nothing \
                   changes nothing and is not recorded.",
    params(("id" = Uuid, Path)),
    request_body(content = MaintenanceWindowUpdate),
    responses(
        (status = 200, body = MaintenanceWindow),
        (status = 400, body = ApiError),
        (status = 404, body = ApiError),
        (status = 422, body = ApiError, description = "Cannot edit a completed or cancelled maintenance window"),
    ),
)]
pub async fn update_maintenance(
    State(state): State<AppState>,
    Authorized(org, _): Authorized<MaintenanceWrite>,
    CurrentUser(actor): CurrentUser,
    RequestSource(source): RequestSource,
    Path(id): Path<Uuid>,
    Json(update): Json<MaintenanceWindowUpdate>,
) -> Result<Json<MaintenanceWindow>> {
    let existing = state.maintenance_store.get(org, id).await?.ok_or_else(|| {
        AppError::not_found(codes::MAINTENANCE_NOT_FOUND, "maintenance window not found")
    })?;
    let mw = state
        .maintenance_ops()
        .update(org, &existing, update, source, Some(actor))
        .await?;
    Ok(Json(mw))
}

#[utoipa::path(
    delete,
    path = "/api/v1/maintenance/{id}",
    tag = "maintenance",
    summary = "Cancel a maintenance window",
    description = "Cancels a window that has not ended. The window is kept as history with \
                   `deleted_at` and `deleted_by` set: it stops showing publicly, stops holding \
                   paging and stops counting toward the quota, and stays listed under `past` and \
                   `all`. Cancelling it again returns 404, and a window that already ended is \
                   history and is rejected with 422.",
    params(("id" = Uuid, Path)),
    responses(
        (status = 204, description = "Cancelled"),
        (status = 404, body = ApiError),
        (status = 422, body = ApiError, description = "Cannot cancel a completed maintenance window"),
    ),
)]
pub async fn delete_maintenance(
    State(state): State<AppState>,
    Authorized(org, _): Authorized<MaintenanceDelete>,
    CurrentUser(actor): CurrentUser,
    RequestSource(source): RequestSource,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    state
        .maintenance_ops()
        .cancel(org, id, source, Some(actor))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/api/v1/maintenance/{id}/updates",
    tag = "maintenance",
    summary = "Post an update to a maintenance window",
    description = "Adds an update to an upcoming, running or completed window, for example to \
                   say the work is running late or how it went. The update shows on the status \
                   page and in its history, and goes to the page's email and webhook \
                   subscribers. Its `phase` is where the window stood when it was posted. A \
                   completed window keeps its own fields read-only; an update is how to add a \
                   closing note. A window takes at most 50 updates. Accepts an \
                   `Idempotency-Key` header, so a retried post is not published twice.",
    params(("id" = Uuid, Path)),
    request_body(content = NewMaintenanceUpdate, example = json!({
        "message": "The data copy is slower than planned. We now expect to finish by 23:30 UTC."
    })),
    responses(
        (status = 201, body = MaintenanceUpdate),
        (status = 400, body = ApiError, description = "Message empty or longer than 2000 characters"),
        (status = 404, body = ApiError),
        (status = 422, body = ApiError,
            description = "The window was cancelled (`MAINTENANCE_CANCELLED`) or already has 50 \
                           updates (`MAINTENANCE_UPDATE_LIMIT`)"),
        (status = 409, body = ApiError,
            description = "A request with the same Idempotency-Key is still running \
                           (`IDEMPOTENCY_IN_PROGRESS`); retry once it answers"),
        ),
)]
pub async fn post_maintenance_update(
    State(state): State<AppState>,
    Authorized(org, _): Authorized<MaintenanceWrite>,
    CurrentUser(actor): CurrentUser,
    Path(id): Path<Uuid>,
    Json(new): Json<NewMaintenanceUpdate>,
) -> Result<(StatusCode, Json<MaintenanceUpdate>)> {
    let update = state
        .maintenance_ops()
        .post_update(org, id, &new.message, Some(actor))
        .await?;
    Ok((StatusCode::CREATED, Json(update)))
}
