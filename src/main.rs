use axum::{
    Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use clap::Parser;
use serde::Deserialize;
use std::sync::Arc;
use tokio::fs;
use tokio_util::io::ReaderStream;
use totp_rs::{Algorithm, Secret, TOTP};

#[derive(Parser, Debug)]
#[command(name = "virtualpapi-db-server")]
#[command(about = "Secure database server with TOTP authentication", long_about = None)]
struct Cli {
    /// Path to the file containing the TOTP secret (Base32 encoded)
    #[arg(short = 's', long)]
    secret_file: String,

    /// Port number to listen on
    #[arg(short = 'p', long)]
    port: u16,

    /// Path to the aviation.db file
    #[arg(short = 'd', long)]
    db_file: String,
}

#[derive(Clone)]
struct AppConfig {
    totp_secret: String,
    db_file: String,
}

#[derive(Deserialize)]
struct TotpQuery {
    totp: String,
}

async fn update_aviation_db(
    State(config): State<Arc<AppConfig>>,
    Query(params): Query<TotpQuery>,
    headers: HeaderMap,
) -> Response {
    // Verify TOTP
    if !verify_totp(&params.totp, &config.totp_secret) {
        return (StatusCode::UNAUTHORIZED, "Invalid TOTP").into_response();
    }

    // Get file metadata to generate ETag
    let metadata = match fs::metadata(&config.db_file).await {
        Ok(meta) => meta,
        Err(e) => {
            eprintln!("Error getting metadata for {}: {}", config.db_file, e);
            return (StatusCode::NOT_FOUND, "Database file not found").into_response();
        }
    };

    let file_size = metadata.len();

    // Generate ETag from file size and modification time
    let etag = match metadata.modified() {
        Ok(mtime) => {
            let duration = mtime
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            format!(
                "\"{}-{}-{}\"",
                file_size,
                duration.as_secs(),
                duration.subsec_nanos()
            )
        }
        Err(e) => {
            eprintln!("Error getting modification time: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error processing file metadata",
            )
                .into_response();
        }
    };

    // Check If-None-Match header
    if let Some(if_none_match) = headers.get(header::IF_NONE_MATCH) {
        if let Ok(if_none_match_str) = if_none_match.to_str() {
            // Check if the ETag matches (supporting both single ETag and comma-separated list)
            if if_none_match_str == "*"
                || if_none_match_str.split(',').any(|tag| tag.trim() == etag)
            {
                return Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .header(header::ETAG, etag)
                    .body(axum::body::Body::empty())
                    .unwrap();
            }
        }
    }

    // Serve the aviation.db file
    match fs::File::open(&config.db_file).await {
        Ok(file) => {
            let stream = ReaderStream::new(file);
            let body = axum::body::Body::from_stream(stream);

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header(
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"aviation.db\"",
                )
                .header(header::CONTENT_LENGTH, file_size)
                .header(header::ETAG, etag)
                .body(body)
                .unwrap()
        }
        Err(e) => {
            eprintln!("Error opening {}: {}", config.db_file, e);
            (StatusCode::NOT_FOUND, "Database file not found").into_response()
        }
    }
}

fn verify_totp(token: &str, secret: &str) -> bool {
    // Parse the secret
    let secret = match Secret::Encoded(secret.to_string()).to_bytes() {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error parsing TOTP secret: {}", e);
            return false;
        }
    };

    // Create TOTP instance
    let totp = match TOTP::new(
        Algorithm::SHA1,
        6,  // 6 digits
        1,  // 1 step (30 seconds per step is default)
        30, // 30 second time step
        secret.to_vec(),
    ) {
        Ok(totp) => totp,
        Err(e) => {
            eprintln!("Error creating TOTP instance: {}", e);
            return false;
        }
    };

    // Verify the token
    match totp.check_current(token) {
        Ok(valid) => valid,
        Err(e) => {
            eprintln!("Error verifying TOTP: {}", e);
            false
        }
    }
}

#[tokio::main]
async fn main() {
    // Parse command-line arguments
    let cli = Cli::parse();

    // Read TOTP secret from file
    let totp_secret = match fs::read_to_string(&cli.secret_file).await {
        Ok(secret) => secret.trim().to_string(),
        Err(e) => {
            eprintln!(
                "Error reading TOTP secret file '{}': {}",
                cli.secret_file, e
            );
            eprintln!("Please create the file with your Base32-encoded TOTP secret.");
            std::process::exit(1);
        }
    };

    // Create application configuration
    let config = Arc::new(AppConfig {
        totp_secret,
        db_file: cli.db_file.clone(),
    });

    // Build the router with shared state
    let app = Router::new()
        .route("/update-aviation-db", get(update_aviation_db))
        .with_state(config);

    // Bind to address
    let addr = format!("0.0.0.0:{}", cli.port);

    println!("=== VirtualPAPI DB Server ===");
    println!("Server starting on {}", addr);
    println!("TOTP secret file: {}", cli.secret_file);
    println!("Database file: {}", cli.db_file);
    println!("Endpoint: GET /update-aviation-db?totp=<token>");
    println!();

    // Start the server
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use totp_rs::{Algorithm, Secret, TOTP};
    use tower::ServiceExt;

    // Test secret (Base32 encoded, 160 bits / 20 bytes)
    const TEST_SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

    // Helper function to generate a valid TOTP token for testing
    fn generate_test_totp(secret: &str) -> String {
        let secret_bytes = Secret::Encoded(secret.to_string()).to_bytes().unwrap();

        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes.to_vec()).unwrap();

        totp.generate_current().unwrap()
    }

    #[test]
    fn test_verify_totp_with_valid_token() {
        let token = generate_test_totp(TEST_SECRET);

        assert!(verify_totp(&token, TEST_SECRET));
    }

    #[test]
    fn test_verify_totp_with_invalid_token() {
        let invalid_token = "000000";

        assert!(!verify_totp(invalid_token, TEST_SECRET));
    }

    #[test]
    fn test_verify_totp_with_malformed_token() {
        let malformed_token = "abc123";

        assert!(!verify_totp(malformed_token, TEST_SECRET));
    }

    #[test]
    fn test_verify_totp_with_invalid_secret() {
        let invalid_secret = "not-a-valid-base32-secret!@#";
        let token = "123456";

        assert!(!verify_totp(token, invalid_secret));
    }

    #[tokio::test]
    async fn test_endpoint_with_valid_totp() {
        // Create a temporary database file
        let mut temp_db = NamedTempFile::new().unwrap();
        temp_db.write_all(b"test database content").unwrap();
        temp_db.flush().unwrap();

        let db_path = temp_db.path().to_str().unwrap().to_string();
        let token = generate_test_totp(TEST_SECRET);

        // Create app config
        let config = Arc::new(AppConfig {
            totp_secret: TEST_SECRET.to_string(),
            db_file: db_path,
        });

        // Build the app
        let app = Router::new()
            .route("/update-aviation-db", get(update_aviation_db))
            .with_state(config);

        // Make request
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/update-aviation-db?totp={}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify content type
        let content_type = response.headers().get("content-type").unwrap();
        assert_eq!(content_type, "application/octet-stream");

        // Verify content
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"test database content");
    }

    #[tokio::test]
    async fn test_endpoint_with_invalid_totp() {
        // Create a temporary database file
        let mut temp_db = NamedTempFile::new().unwrap();
        temp_db.write_all(b"test database content").unwrap();
        temp_db.flush().unwrap();

        let db_path = temp_db.path().to_str().unwrap().to_string();
        let invalid_token = "000000";

        // Create app config
        let config = Arc::new(AppConfig {
            totp_secret: TEST_SECRET.to_string(),
            db_file: db_path,
        });

        // Build the app
        let app = Router::new()
            .route("/update-aviation-db", get(update_aviation_db))
            .with_state(config);

        // Make request with invalid token
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/update-aviation-db?totp={}", invalid_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_endpoint_with_missing_totp_parameter() {
        // Create a temporary database file
        let mut temp_db = NamedTempFile::new().unwrap();
        temp_db.write_all(b"test database content").unwrap();
        temp_db.flush().unwrap();

        let db_path = temp_db.path().to_str().unwrap().to_string();

        // Create app config
        let config = Arc::new(AppConfig {
            totp_secret: TEST_SECRET.to_string(),
            db_file: db_path,
        });

        // Build the app
        let app = Router::new()
            .route("/update-aviation-db", get(update_aviation_db))
            .with_state(config);

        // Make request without totp parameter
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/update-aviation-db")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should fail with BAD_REQUEST due to missing required query parameter
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_endpoint_with_nonexistent_database() {
        let token = generate_test_totp(TEST_SECRET);

        // Create app config with nonexistent db file
        let config = Arc::new(AppConfig {
            totp_secret: TEST_SECRET.to_string(),
            db_file: "/nonexistent/path/to/database.db".to_string(),
        });

        // Build the app
        let app = Router::new()
            .route("/update-aviation-db", get(update_aviation_db))
            .with_state(config);

        // Make request
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/update-aviation-db?totp={}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_endpoint_headers() {
        // Create a temporary database file
        let mut temp_db = NamedTempFile::new().unwrap();
        temp_db.write_all(b"test content").unwrap();
        temp_db.flush().unwrap();

        let db_path = temp_db.path().to_str().unwrap().to_string();
        let token = generate_test_totp(TEST_SECRET);

        // Create app config
        let config = Arc::new(AppConfig {
            totp_secret: TEST_SECRET.to_string(),
            db_file: db_path,
        });

        // Build the app
        let app = Router::new()
            .route("/update-aviation-db", get(update_aviation_db))
            .with_state(config);

        // Make request
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/update-aviation-db?totp={}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Check Content-Type header
        let content_type = response.headers().get("content-type").unwrap();
        assert_eq!(content_type, "application/octet-stream");

        // Check Content-Disposition header
        let content_disposition = response.headers().get("content-disposition").unwrap();
        assert_eq!(content_disposition, "attachment; filename=\"aviation.db\"");
    }

    #[tokio::test]
    async fn test_etag_header_present() {
        // Create a temporary database file
        let mut temp_db = NamedTempFile::new().unwrap();
        temp_db.write_all(b"test content").unwrap();
        temp_db.flush().unwrap();

        let db_path = temp_db.path().to_str().unwrap().to_string();
        let token = generate_test_totp(TEST_SECRET);

        // Create app config
        let config = Arc::new(AppConfig {
            totp_secret: TEST_SECRET.to_string(),
            db_file: db_path,
        });

        // Build the app
        let app = Router::new()
            .route("/update-aviation-db", get(update_aviation_db))
            .with_state(config);

        // Make request
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/update-aviation-db?totp={}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Check ETag header is present
        let etag = response.headers().get("etag");
        assert!(etag.is_some(), "ETag header should be present");

        // Verify ETag format (should be quoted and contain size and timestamp)
        let etag_value = etag.unwrap().to_str().unwrap();
        assert!(etag_value.starts_with('"') && etag_value.ends_with('"'));
        assert!(etag_value.contains('-')); // Should contain hyphens separating size and time
    }

    #[tokio::test]
    async fn test_etag_not_modified() {
        // Create a temporary database file
        let mut temp_db = NamedTempFile::new().unwrap();
        temp_db.write_all(b"test content").unwrap();
        temp_db.flush().unwrap();

        let db_path = temp_db.path().to_str().unwrap().to_string();
        let token = generate_test_totp(TEST_SECRET);

        // Create app config
        let config = Arc::new(AppConfig {
            totp_secret: TEST_SECRET.to_string(),
            db_file: db_path,
        });

        // Build the app
        let app = Router::new()
            .route("/update-aviation-db", get(update_aviation_db))
            .with_state(config.clone());

        // First request to get the ETag
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/update-aviation-db?totp={}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let etag = response.headers().get("etag").unwrap().to_str().unwrap();

        // Generate a new token for the second request
        let token2 = generate_test_totp(TEST_SECRET);

        // Second request with If-None-Match header
        let app2 = Router::new()
            .route("/update-aviation-db", get(update_aviation_db))
            .with_state(config);

        let response2 = app2
            .oneshot(
                Request::builder()
                    .uri(format!("/update-aviation-db?totp={}", token2))
                    .header("If-None-Match", etag)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 304 Not Modified
        assert_eq!(response2.status(), StatusCode::NOT_MODIFIED);

        // ETag should still be present in 304 response
        let etag2 = response2.headers().get("etag").unwrap().to_str().unwrap();
        assert_eq!(etag, etag2);

        // Body should be empty for 304 response
        let body = response2.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.len(), 0);
    }

    #[tokio::test]
    async fn test_etag_mismatch_serves_file() {
        // Create a temporary database file
        let mut temp_db = NamedTempFile::new().unwrap();
        temp_db.write_all(b"test content").unwrap();
        temp_db.flush().unwrap();

        let db_path = temp_db.path().to_str().unwrap().to_string();
        let token = generate_test_totp(TEST_SECRET);

        // Create app config
        let config = Arc::new(AppConfig {
            totp_secret: TEST_SECRET.to_string(),
            db_file: db_path,
        });

        // Build the app
        let app = Router::new()
            .route("/update-aviation-db", get(update_aviation_db))
            .with_state(config);

        // Make request with a mismatched If-None-Match header
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/update-aviation-db?totp={}", token))
                    .header("If-None-Match", "\"wrong-etag\"")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 200 OK and serve the file
        assert_eq!(response.status(), StatusCode::OK);

        // Verify content is served
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"test content");
    }

    #[tokio::test]
    async fn test_content_length_header() {
        // Create a temporary database file with known content
        let mut temp_db = NamedTempFile::new().unwrap();
        let test_content = b"test content with specific length";
        temp_db.write_all(test_content).unwrap();
        temp_db.flush().unwrap();

        let db_path = temp_db.path().to_str().unwrap().to_string();
        let token = generate_test_totp(TEST_SECRET);

        // Create app config
        let config = Arc::new(AppConfig {
            totp_secret: TEST_SECRET.to_string(),
            db_file: db_path,
        });

        // Build the app
        let app = Router::new()
            .route("/update-aviation-db", get(update_aviation_db))
            .with_state(config);

        // Make request
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/update-aviation-db?totp={}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Check Content-Length header is present and correct
        let content_length = response.headers().get("content-length");
        assert!(
            content_length.is_some(),
            "Content-Length header should be present"
        );

        let content_length_value = content_length.unwrap().to_str().unwrap();
        assert_eq!(
            content_length_value,
            test_content.len().to_string(),
            "Content-Length should match file size"
        );
    }
}
