/// Errors never contain credential material. HTTP response bodies are reduced
/// to Google's non-sensitive status/message fields before entering this type.
#[derive(Debug, thiserror::Error)]
pub enum GcpError {
    #[error("Google Cloud CLI is unavailable")]
    GcloudUnavailable,
    #[error("the isolated Google Cloud CLI session is not authenticated")]
    GcloudUnauthenticated,
    #[error("authentication failed: {0}")]
    Authentication(String),
    #[error("GCP contract violation: {0}")]
    Contract(String),
    #[error("GCP resource was not found: {0}")]
    NotFound(String),
    #[error("GCP request failed ({status}): {message}")]
    Api { status: u16, message: String },
    #[error("GCP infrastructure failure: {0}")]
    Infrastructure(String),
    #[error("I/O failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

impl GcpError {
    pub(crate) fn safe_api(status: u16, body: &[u8]) -> Self {
        #[derive(serde::Deserialize)]
        struct Envelope {
            error: Option<ApiError>,
        }
        #[derive(serde::Deserialize)]
        struct ApiError {
            message: Option<String>,
            status: Option<String>,
        }

        let parsed = serde_json::from_slice::<Envelope>(body).ok();
        let message = parsed.and_then(|value| value.error).map_or_else(
            || "request rejected (response body redacted)".to_owned(),
            |error| match (error.status, error.message) {
                (Some(code), Some(message)) => format!("{code}: {message}"),
                (Some(code), None) => code,
                (None, Some(message)) => message,
                (None, None) => "request rejected".to_owned(),
            },
        );
        Self::Api { status, message }
    }
}

pub type Result<T> = std::result::Result<T, GcpError>;
