//! Serves the example router on localhost. Cookie server functions resolve
//! through the same stack the tests exercise.

use fullstack_app::{app_config, app_router};

#[tokio::main]
async fn main() {
    let router = app_router(app_config());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("example must bind localhost");
    println!("serving the fullstack demo on http://127.0.0.1:8080");
    axum::serve(listener, router)
        .await
        .expect("example server must serve");
}
