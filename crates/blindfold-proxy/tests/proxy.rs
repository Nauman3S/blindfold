//! End-to-end proxy tests with a fake allowlisted upstream.

use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::State,
    http::{HeaderValue, Request, Response, StatusCode, header::CONTENT_TYPE},
    response::IntoResponse,
    routing::post,
};
use blindfold_proxy::{Config, ExactValueSanitizer, Provider, Proxy, TraceSink, Upstream};
use blindfold_trace::Record;
use tokio::{net::TcpListener, sync::oneshot};
use tokio_util::sync::CancellationToken;

const SECRET: &str = "raw-secret-value";

#[derive(Clone, Default)]
struct Capture {
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
}

#[derive(Clone)]
struct UpstreamState {
    capture: Capture,
    response: Arc<Mutex<Option<Response<Body>>>>,
}

#[derive(Clone, Default)]
struct TraceCapture {
    records: Arc<Mutex<Vec<Record>>>,
}

impl TraceSink for TraceCapture {
    fn record(&self, record: Record) {
        if let Ok(mut records) = self.records.lock() {
            records.push(record);
        }
    }
}

#[tokio::test]
async fn fake_upstream_never_receives_raw_openai_value() -> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let (upstream, upstream_stop) = spawn_upstream(capture.clone(), openai_response()).await?;
    let (proxy, proxy_stop) = spawn_proxy(upstream, Provider::OpenAi).await?;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{proxy}/openai/v1/chat/completions"))
        .header(CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(&serde_json::json!({
            "model": "test-model",
            "messages": [{"role": "user", "content": format!("send {SECRET}")}]
        }))?)
        .send()
        .await?;
    let response_text = response.text().await?;

    let captured = capture.bodies.lock().map_err(|_| "capture poisoned")?;
    assert_eq!(captured.len(), 1);
    let upstream_body = std::str::from_utf8(&captured[0])?;
    assert!(!upstream_body.contains(SECRET));
    assert!(upstream_body.contains("[REDACTED]"));
    assert!(!response_text.contains(SECRET));
    assert!(response_text.contains("[REDACTED]"));

    proxy_stop.cancel();
    let _ = upstream_stop.send(());
    Ok(())
}

#[tokio::test]
async fn explicit_trace_sink_receives_payload_free_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let traces = TraceCapture::default();
    let (upstream, upstream_stop) = spawn_upstream(capture, openai_response()).await?;
    let config = proxy_config(upstream, Provider::OpenAi)?;
    let sanitizer = Arc::new(ExactValueSanitizer::new(SECRET, "[REDACTED]")?);
    let bound = Proxy::new(config, sanitizer)?
        .with_trace_sink(Arc::new(traces.clone()))
        .bind()
        .await?;
    let address = bound.local_addr();
    let proxy_stop = CancellationToken::new();
    let serving_token = proxy_stop.clone();
    tokio::spawn(async move {
        let _ = bound.serve(serving_token).await;
    });

    reqwest::Client::new()
        .post(format!("http://{address}/openai/v1/chat/completions"))
        .header(CONTENT_TYPE, "application/json")
        .body(format!(
            r#"{{"messages":[{{"role":"user","content":"send {SECRET}"}}]}}"#
        ))
        .send()
        .await?
        .error_for_status()?;

    let records = traces
        .records
        .lock()
        .map_err(|_| "trace capture poisoned")?;
    assert_eq!(records.len(), 1);
    let json = records[0].to_json()?;
    assert!(!json.contains(SECRET));
    assert!(!json.contains("[REDACTED]"));
    assert!(json.contains("\"coverage\":\"protected\""));
    assert!(json.contains("\"pointer\":\"/messages/0/content\""));

    proxy_stop.cancel();
    let _ = upstream_stop.send(());
    Ok(())
}

#[tokio::test]
async fn sanitizes_nested_openai_tool_arguments_end_to_end()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let response = json_response(&serde_json::json!({
        "choices": [{
            "message": {
                "tool_calls": [{
                    "type": "function",
                    "function": {
                        "name": "lookup",
                        "arguments": format!("{{\"result\":\"{SECRET}\"}}")
                    }
                }]
            }
        }]
    }))?;
    let (upstream, upstream_stop) = spawn_upstream(capture.clone(), response).await?;
    let (proxy, proxy_stop) = spawn_proxy(upstream, Provider::OpenAi).await?;

    let response = reqwest::Client::new()
        .post(format!("{proxy}/openai/v1/chat/completions"))
        .header(CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(&serde_json::json!({
            "messages": [{
                "role": "assistant",
                "tool_calls": [{
                    "type": "function",
                    "function": {
                        "name": "lookup",
                        "arguments": format!("{{\"query\":\"{SECRET}\"}}")
                    }
                }]
            }]
        }))?)
        .send()
        .await?;
    let response_text = response.text().await?;

    let captured = capture.bodies.lock().map_err(|_| "capture poisoned")?;
    assert!(!std::str::from_utf8(&captured[0])?.contains(SECRET));
    assert!(!response_text.contains(SECRET));
    assert!(response_text.contains("[REDACTED]"));

    proxy_stop.cancel();
    let _ = upstream_stop.send(());
    Ok(())
}

#[tokio::test]
async fn sanitizes_anthropic_tool_payloads_end_to_end() -> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let response = json_response(&serde_json::json!({
        "content": [{
            "type": "tool_use",
            "name": "lookup",
            "input": {"result": SECRET, "nested": [{"note": SECRET}]}
        }]
    }))?;
    let (upstream, upstream_stop) = spawn_upstream(capture.clone(), response).await?;
    let (proxy, proxy_stop) = spawn_proxy(upstream, Provider::Anthropic).await?;

    let response = reqwest::Client::new()
        .post(format!("{proxy}/anthropic/v1/messages"))
        .header(CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(&serde_json::json!({
            "messages": [{
                "role": "user",
                "content": [{
                    "type": "tool_use",
                    "name": "lookup",
                    "input": {"query": SECRET, "nested": [SECRET]}
                }]
            }]
        }))?)
        .send()
        .await?;
    let response_text = response.text().await?;

    let captured = capture.bodies.lock().map_err(|_| "capture poisoned")?;
    assert!(!std::str::from_utf8(&captured[0])?.contains(SECRET));
    assert!(!response_text.contains(SECRET));
    assert!(response_text.contains("[REDACTED]"));

    proxy_stop.cancel();
    let _ = upstream_stop.send(());
    Ok(())
}

#[tokio::test]
async fn split_sse_chunks_are_withheld_and_sanitized() -> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let (upstream, upstream_stop) = spawn_upstream(capture, split_sse_response()).await?;
    let (proxy, proxy_stop) = spawn_proxy(upstream, Provider::Anthropic).await?;

    let response = reqwest::Client::new()
        .post(format!("{proxy}/anthropic/v1/messages"))
        .header(CONTENT_TYPE, "application/json")
        .body(r#"{"messages":[{"role":"user","content":"hello"}]}"#)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(!body.contains(SECRET));
    assert!(body.contains("[REDACTED]"));

    proxy_stop.cancel();
    let _ = upstream_stop.send(());
    Ok(())
}

#[tokio::test]
async fn rejects_proxy_hop_marker() -> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let (upstream, upstream_stop) = spawn_upstream(capture, openai_response()).await?;
    let (proxy, proxy_stop) = spawn_proxy(upstream, Provider::OpenAi).await?;

    let response = reqwest::Client::new()
        .post(format!("{proxy}/openai/v1/chat/completions"))
        .header("x-blindfold-proxy-hop", "1")
        .header(CONTENT_TYPE, "application/json")
        .body("{}")
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::LOOP_DETECTED);
    let body = response.text().await?;
    assert!(!body.contains(SECRET));
    assert!(body.contains("proxy_loop"));

    proxy_stop.cancel();
    let _ = upstream_stop.send(());
    Ok(())
}

#[tokio::test]
async fn bounds_chunked_upstream_responses() -> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let response = streamed_response(
        [Bytes::from(vec![b'a'; 40]), Bytes::from(vec![b'b'; 40])],
        "application/octet-stream",
    );
    let (upstream, upstream_stop) = spawn_upstream(capture, response).await?;
    let config = Config {
        max_response_body: 64,
        ..proxy_config(upstream, Provider::OpenAi)?
    };
    let (proxy, proxy_stop) = spawn_proxy_with_config(config).await?;

    let response = reqwest::Client::new()
        .post(format!("{proxy}/openai/v1/chat/completions"))
        .header(CONTENT_TYPE, "application/json")
        .body("{}")
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(response.text().await?.contains("response_too_large"));

    proxy_stop.cancel();
    let _ = upstream_stop.send(());
    Ok(())
}

#[tokio::test]
async fn rejects_non_empty_unsupported_request_content_type()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let (upstream, upstream_stop) = spawn_upstream(capture.clone(), openai_response()).await?;
    let (proxy, proxy_stop) = spawn_proxy(upstream, Provider::OpenAi).await?;

    let response = reqwest::Client::new()
        .post(format!("{proxy}/openai/v1/chat/completions"))
        .header(CONTENT_TYPE, "text/plain")
        .body(SECRET)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.text().await?.contains("invalid_request"));
    assert!(
        capture
            .bodies
            .lock()
            .map_err(|_| "capture poisoned")?
            .is_empty()
    );

    proxy_stop.cancel();
    let _ = upstream_stop.send(());
    Ok(())
}

#[tokio::test]
async fn rejects_non_empty_unsupported_response_content_type()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let response = Response::builder()
        .header(CONTENT_TYPE, "text/plain")
        .body(Body::from(SECRET))?;
    let (upstream, upstream_stop) = spawn_upstream(capture, response).await?;
    let (proxy, proxy_stop) = spawn_proxy(upstream, Provider::OpenAi).await?;

    let response = reqwest::Client::new()
        .post(format!("{proxy}/openai/v1/chat/completions"))
        .header(CONTENT_TYPE, "application/json")
        .body("{}")
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body = response.text().await?;
    assert!(!body.contains(SECRET));
    assert!(body.contains("upstream_failure"));

    proxy_stop.cancel();
    let _ = upstream_stop.send(());
    Ok(())
}

#[tokio::test]
async fn allows_empty_bodies_with_unsupported_content_types()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let response = Response::builder()
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(Body::empty())?;
    let (upstream, upstream_stop) = spawn_upstream(capture.clone(), response).await?;
    let (proxy, proxy_stop) = spawn_proxy(upstream, Provider::OpenAi).await?;

    let response = reqwest::Client::new()
        .post(format!("{proxy}/openai/v1/chat/completions"))
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(Vec::new())
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.bytes().await?.is_empty());
    assert_eq!(
        capture
            .bodies
            .lock()
            .map_err(|_| "capture poisoned")?
            .as_slice(),
        &[Vec::<u8>::new()]
    );

    proxy_stop.cancel();
    let _ = upstream_stop.send(());
    Ok(())
}

async fn spawn_proxy(
    upstream_addr: std::net::SocketAddr,
    provider: Provider,
) -> Result<(String, CancellationToken), Box<dyn std::error::Error>> {
    spawn_proxy_with_config(proxy_config(upstream_addr, provider)?).await
}

fn proxy_config(
    upstream_addr: std::net::SocketAddr,
    provider: Provider,
) -> Result<Config, Box<dyn std::error::Error>> {
    let route_name = match provider {
        Provider::OpenAi => "openai",
        Provider::Anthropic => "anthropic",
    };
    let mut config = Config {
        request_timeout: Duration::from_secs(5),
        stream_overlap: SECRET.len(),
        ..Config::default()
    };
    config.upstreams.push(Upstream::new(
        route_name,
        format!("http://{upstream_addr}"),
        provider,
    )?);
    Ok(config)
}

async fn spawn_proxy_with_config(
    config: Config,
) -> Result<(String, CancellationToken), Box<dyn std::error::Error>> {
    let sanitizer = Arc::new(ExactValueSanitizer::new(SECRET, "[REDACTED]")?);
    let bound = Proxy::new(config, sanitizer)?.bind().await?;
    let address = bound.local_addr();
    let cancellation = CancellationToken::new();
    let serving_token = cancellation.clone();
    tokio::spawn(async move {
        let _ = bound.serve(serving_token).await;
    });
    Ok((format!("http://{address}"), cancellation))
}

async fn spawn_upstream(
    capture: Capture,
    response: Response<Body>,
) -> Result<(std::net::SocketAddr, oneshot::Sender<()>), Box<dyn std::error::Error>> {
    let response = Arc::new(Mutex::new(Some(response)));
    let app = Router::new()
        .route("/v1/chat/completions", post(capture_and_respond))
        .route("/v1/messages", post(capture_and_respond))
        .with_state(UpstreamState { capture, response });
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (stop_tx, stop_rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = stop_rx.await;
            })
            .await;
    });
    Ok((address, stop_tx))
}

async fn capture_and_respond(
    State(state): State<UpstreamState>,
    request: Request<Body>,
) -> Response<Body> {
    let Ok(body) = to_bytes(request.into_body(), 1024 * 1024).await else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if let Ok(mut bodies) = state.capture.bodies.lock() {
        bodies.push(body.to_vec());
    }
    match state.response.lock() {
        Ok(mut response) => response.take().unwrap_or_else(|| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap_or_else(|_| Response::new(Body::empty()))
        }),
        Err(_) => Response::new(Body::empty()),
    }
}

fn openai_response() -> Response<Body> {
    Response::builder()
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(format!(
            r#"{{"choices":[{{"message":{{"content":"echo {SECRET}"}}}}]}}"#
        )))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn json_response(value: &serde_json::Value) -> Result<Response<Body>, serde_json::Error> {
    Ok(Response::builder()
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&value)?))
        .unwrap_or_else(|_| Response::new(Body::empty())))
}

fn split_sse_response() -> Response<Body> {
    let first = format!(
        "event: content_block_delta\ndata: {{\"delta\":{{\"type\":\"text_delta\",\"text\":\"{}",
        &SECRET[..7]
    );
    let second = format!("{}\"}}}}\n\n", &SECRET[7..]);
    streamed_response(
        [Bytes::from(first), Bytes::from(second)],
        "text/event-stream",
    )
}

fn streamed_response<const N: usize>(
    chunks: [Bytes; N],
    content_type: &'static str,
) -> Response<Body> {
    let stream = futures_util::stream::iter(chunks.map(Ok::<Bytes, Infallible>));
    let mut response = Response::new(Body::from_stream(stream));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}
