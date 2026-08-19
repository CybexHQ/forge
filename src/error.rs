use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid request: {0}")]
    Validation(String),
    #[error("not found")]
    NotFound,
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("configuration error: {0}")]
    Config(String),
    #[error("path is not allowed")]
    UnsafePath,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: ErrorBody,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub code: &'static str,
    pub message: String,
}

impl AppError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Validation(_) => StatusCode::BAD_REQUEST,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden | Self::UnsafePath => StatusCode::FORBIDDEN,
            Self::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Sqlx(_) | Self::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Validation(_) => "validation_error",
            Self::NotFound => "not_found",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::UnsafePath => "unsafe_path",
            Self::Config(_) => "configuration_error",
            Self::Sqlx(_) => "database_error",
            Self::Io(_) => "io_error",
        }
    }

    pub fn response_message(&self) -> String {
        match self {
            Self::Sqlx(_) | Self::Io(_) | Self::Config(_) => "internal server error".to_string(),
            Self::Validation(_)
            | Self::NotFound
            | Self::Unauthorized
            | Self::Forbidden
            | Self::UnsafePath => self.to_string(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let code = self.code();
        let message = self.response_message();
        let body = ErrorResponse {
            error: ErrorBody { code, message },
        };

        (status, Json(body)).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::AppError;

    #[test]
    fn internal_error_responses_are_generic() {
        let err = AppError::Config("database_path = /var/lib/cybex-james/private".to_string());

        assert_eq!(err.code(), "configuration_error");
        assert_eq!(err.response_message(), "internal server error");
    }

    #[test]
    fn validation_error_responses_remain_actionable() {
        let err = AppError::Validation("invalid MAC address".to_string());

        assert_eq!(err.code(), "validation_error");
        assert_eq!(
            err.response_message(),
            "invalid request: invalid MAC address"
        );
    }
}
