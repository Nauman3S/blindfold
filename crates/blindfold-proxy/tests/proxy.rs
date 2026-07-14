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
    http::{
        HeaderMap, HeaderValue, Request, Response, StatusCode,
        header::{ACCEPT_ENCODING, AUTHORIZATION, CONTENT_TYPE},
    },
    response::IntoResponse,
    routing::post,
};
use blindfold_proxy::{
    Config, ConfigError, ExactValueSanitizer, Provider, Proxy, TraceSink, Upstream,
};
use blindfold_trace::Record;
use futures_util::{SinkExt, StreamExt};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot},
};
use tokio_tungstenite::{
    accept_async, connect_async,
    tungstenite::{
        Message as WsMessage,
        client::IntoClientRequest,
        protocol::frame::{
            Frame,
            coding::{Data, OpCode},
        },
    },
};
use tokio_util::sync::CancellationToken;

const SECRET: &str = "raw-secret-value";
const TRUSTED_CREDENTIAL: &str = "trusted-gateway-credential";

#[derive(Clone, Default)]
struct Capture {
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    headers: Arc<Mutex<Vec<HeaderMap>>>,
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
async fn rejects_sensitive_path_query_and_custom_header_before_upstream()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let (upstream, upstream_stop) = spawn_upstream(capture.clone(), openai_response()).await?;
    let (proxy, proxy_stop) = spawn_proxy(upstream, Provider::OpenAi).await?;
    let client = reqwest::Client::new();

    let requests = [
        client
            .post(format!(
                "{proxy}/openai/v1/chat/completions?api_key={SECRET}"
            ))
            .header(CONTENT_TYPE, "application/json"),
        client
            .post(format!("{proxy}/openai/v1/chat/completions"))
            .header(CONTENT_TYPE, "application/json")
            .header("x-client-secret", SECRET),
        client
            .post(format!("{proxy}/openai/v1/{SECRET}"))
            .header(CONTENT_TYPE, "application/json"),
    ];
    for request in requests {
        let response = request.body(r#"{"model":"test-model"}"#).send().await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let text = response.text().await?;
        assert!(text.contains("sensitive_metadata"));
        assert!(!text.contains(SECRET));
    }

    assert!(
        capture
            .bodies
            .lock()
            .map_err(|_| "capture poisoned")?
            .is_empty()
    );
    assert!(
        capture
            .headers
            .lock()
            .map_err(|_| "capture poisoned")?
            .is_empty()
    );
    proxy_stop.cancel();
    let _ = upstream_stop.send(());
    Ok(())
}

#[tokio::test]
async fn provider_authentication_header_is_forwarded_to_allowlisted_upstream()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let (upstream, upstream_stop) = spawn_upstream(capture.clone(), openai_response()).await?;
    let (proxy, proxy_stop) = spawn_proxy(upstream, Provider::OpenAi).await?;

    reqwest::Client::new()
        .post(format!("{proxy}/openai/v1/chat/completions"))
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {SECRET}"))
        .body(r#"{"model":"test-model"}"#)
        .send()
        .await?
        .error_for_status()?;

    let headers = capture.headers.lock().map_err(|_| "capture poisoned")?;
    assert_eq!(headers.len(), 1);
    assert_eq!(
        headers[0]
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer raw-secret-value")
    );
    proxy_stop.cancel();
    let _ = upstream_stop.send(());
    Ok(())
}

#[tokio::test]
async fn anthropic_root_head_probe_is_answered_locally_without_upstream()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let (upstream, upstream_stop) = spawn_upstream(capture.clone(), openai_response()).await?;
    let (proxy, proxy_stop) = spawn_proxy(upstream, Provider::Anthropic).await?;

    let response = reqwest::Client::new()
        .head(format!("{proxy}/anthropic"))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        capture
            .headers
            .lock()
            .map_err(|_| "capture poisoned")?
            .is_empty()
    );

    proxy_stop.cancel();
    let _ = upstream_stop.send(());
    Ok(())
}

#[tokio::test]
async fn gateway_openai_credential_replaces_all_client_provider_auth_headers()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let (upstream, upstream_stop) = spawn_upstream(capture.clone(), openai_response()).await?;
    let config =
        proxy_config_with_gateway_credential(upstream, Provider::OpenAi, TRUSTED_CREDENTIAL)?;
    let (proxy, proxy_stop) = spawn_proxy_with_config(config).await?;

    reqwest::Client::new()
        .post(format!("{proxy}/openai/v1/chat/completions"))
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, "Bearer client-spoof")
        .header("x-api-key", "client-spoof")
        .header("api-key", "client-spoof")
        .header(ACCEPT_ENCODING, "gzip, deflate, br, zstd")
        .body(r#"{"model":"test-model"}"#)
        .send()
        .await?
        .error_for_status()?;

    let headers = capture.headers.lock().map_err(|_| "capture poisoned")?;
    assert_eq!(headers.len(), 1);
    assert_eq!(
        headers[0]
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer trusted-gateway-credential")
    );
    assert!(!headers[0].contains_key("x-api-key"));
    assert!(!headers[0].contains_key("api-key"));
    assert!(!headers[0].contains_key(ACCEPT_ENCODING));

    proxy_stop.cancel();
    let _ = upstream_stop.send(());
    Ok(())
}

#[tokio::test]
async fn gateway_anthropic_credential_replaces_all_client_provider_auth_headers()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let (upstream, upstream_stop) = spawn_upstream(capture.clone(), openai_response()).await?;
    let config =
        proxy_config_with_gateway_credential(upstream, Provider::Anthropic, TRUSTED_CREDENTIAL)?;
    let (proxy, proxy_stop) = spawn_proxy_with_config(config).await?;

    reqwest::Client::new()
        .post(format!("{proxy}/anthropic/v1/messages"))
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, "Bearer client-spoof")
        .header("x-api-key", "client-spoof")
        .header("api-key", "client-spoof")
        .body(r#"{"model":"test-model"}"#)
        .send()
        .await?
        .error_for_status()?;

    let headers = capture.headers.lock().map_err(|_| "capture poisoned")?;
    assert_eq!(headers.len(), 1);
    assert_eq!(
        headers[0]
            .get("x-api-key")
            .and_then(|value| value.to_str().ok()),
        Some(TRUSTED_CREDENTIAL)
    );
    assert!(!headers[0].contains_key(AUTHORIZATION));
    assert!(!headers[0].contains_key("api-key"));

    proxy_stop.cancel();
    let _ = upstream_stop.send(());
    Ok(())
}

#[tokio::test]
async fn gateway_credential_is_sanitized_from_payloads_in_both_directions()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let response = json_response(&serde_json::json!({"output": TRUSTED_CREDENTIAL}))?;
    let (upstream, upstream_stop) = spawn_upstream(capture.clone(), response).await?;
    let config =
        proxy_config_with_gateway_credential(upstream, Provider::OpenAi, TRUSTED_CREDENTIAL)?;
    let (proxy, proxy_stop) = spawn_proxy_with_config(config).await?;

    let response = reqwest::Client::new()
        .post(format!("{proxy}/openai/v1/chat/completions"))
        .header(CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(&serde_json::json!({
            "input": TRUSTED_CREDENTIAL
        }))?)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    let bodies = capture.bodies.lock().map_err(|_| "capture poisoned")?;
    assert_eq!(bodies.len(), 1);
    assert!(!std::str::from_utf8(&bodies[0])?.contains(TRUSTED_CREDENTIAL));
    assert!(!response.contains(TRUSTED_CREDENTIAL));
    assert!(response.contains("[REDACTED]"));

    proxy_stop.cancel();
    let _ = upstream_stop.send(());
    Ok(())
}

#[tokio::test]
async fn gateway_credential_rejects_non_model_endpoint_before_upstream()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let (upstream, upstream_stop) = spawn_upstream(capture.clone(), openai_response()).await?;
    let config =
        proxy_config_with_gateway_credential(upstream, Provider::OpenAi, TRUSTED_CREDENTIAL)?;
    let (proxy, proxy_stop) = spawn_proxy_with_config(config).await?;

    let response = reqwest::Client::new()
        .post(format!("{proxy}/openai/v1/files"))
        .header(CONTENT_TYPE, "application/json")
        .body("{}")
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.text().await?.contains("invalid_request"));
    assert!(
        capture
            .headers
            .lock()
            .map_err(|_| "capture poisoned")?
            .is_empty()
    );

    proxy_stop.cancel();
    let _ = upstream_stop.send(());
    Ok(())
}

#[tokio::test]
async fn gateway_credential_rejects_model_endpoint_query_before_upstream()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let (upstream, upstream_stop) = spawn_upstream(capture.clone(), openai_response()).await?;
    let config =
        proxy_config_with_gateway_credential(upstream, Provider::OpenAi, TRUSTED_CREDENTIAL)?;
    let (proxy, proxy_stop) = spawn_proxy_with_config(config).await?;

    let response = reqwest::Client::new()
        .post(format!("{proxy}/openai/v1/responses?metadata=opaque"))
        .header(CONTENT_TYPE, "application/json")
        .body(r#"{"model":"test-model"}"#)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        capture
            .headers
            .lock()
            .map_err(|_| "capture poisoned")?
            .is_empty()
    );

    proxy_stop.cancel();
    let _ = upstream_stop.send(());
    Ok(())
}

#[tokio::test]
async fn gateway_anthropic_credential_accepts_only_the_required_beta_query()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let (upstream, upstream_stop) = spawn_upstream(capture.clone(), openai_response()).await?;
    let config =
        proxy_config_with_gateway_credential(upstream, Provider::Anthropic, TRUSTED_CREDENTIAL)?;
    let (proxy, proxy_stop) = spawn_proxy_with_config(config).await?;

    reqwest::Client::new()
        .post(format!("{proxy}/anthropic/v1/messages?beta=true"))
        .header(CONTENT_TYPE, "application/json")
        .body(r#"{"model":"test-model"}"#)
        .send()
        .await?
        .error_for_status()?;
    assert_eq!(
        capture
            .headers
            .lock()
            .map_err(|_| "capture poisoned")?
            .len(),
        1
    );

    proxy_stop.cancel();
    let _ = upstream_stop.send(());
    Ok(())
}

#[test]
fn gateway_credential_is_redacted_from_debug_output() -> Result<(), Box<dyn std::error::Error>> {
    let upstream = Upstream::new("openai", "https://api.example.test", Provider::OpenAi)?
        .with_gateway_credential(TRUSTED_CREDENTIAL)?;
    let upstream_debug = format!("{upstream:?}");
    assert!(!upstream_debug.contains(TRUSTED_CREDENTIAL));
    assert!(upstream_debug.contains("[REDACTED]"));

    let config = Config {
        upstreams: vec![upstream],
        ..Config::default()
    };
    assert!(!format!("{config:?}").contains(TRUSTED_CREDENTIAL));
    Ok(())
}

#[tokio::test]
async fn fragmented_websocket_json_is_reassembled_and_sanitized_in_both_directions()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_address = listener.local_addr()?;
    let (capture_tx, mut capture_rx) = mpsc::channel(1);
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut socket) = accept_async(stream).await else {
            return;
        };
        let Some(Ok(WsMessage::Text(text))) = socket.next().await else {
            return;
        };
        let _ = capture_tx.send(text.to_string()).await;
        let response = format!(r#"{{"delta":"echo {SECRET}"}}"#);
        let Some(split) = response.find(SECRET).map(|index| index + 7) else {
            return;
        };
        let _ = socket
            .send(WsMessage::Frame(Frame::message(
                Bytes::copy_from_slice(&response.as_bytes()[..split]),
                OpCode::Data(Data::Text),
                false,
            )))
            .await;
        let _ = socket
            .send(WsMessage::Frame(Frame::message(
                Bytes::copy_from_slice(&response.as_bytes()[split..]),
                OpCode::Data(Data::Continue),
                true,
            )))
            .await;
    });
    let (proxy, proxy_stop) = spawn_proxy(upstream_address, Provider::OpenAi).await?;

    let websocket_url = proxy.replacen("http://", "ws://", 1) + "/openai/v1/responses";
    let (mut client, _) = connect_async(websocket_url).await?;
    let request = format!(r#"{{"input":"send {SECRET}"}}"#);
    let split = request.find(SECRET).ok_or("fixture missing")? + 7;
    client
        .send(WsMessage::Frame(Frame::message(
            Bytes::copy_from_slice(&request.as_bytes()[..split]),
            OpCode::Data(Data::Text),
            false,
        )))
        .await?;
    client
        .send(WsMessage::Frame(Frame::message(
            Bytes::copy_from_slice(&request.as_bytes()[split..]),
            OpCode::Data(Data::Continue),
            true,
        )))
        .await?;
    let upstream_text = capture_rx.recv().await.ok_or("missing upstream frame")?;
    assert!(!upstream_text.contains(SECRET));
    assert!(upstream_text.contains("[REDACTED]"));
    let Some(WsMessage::Text(client_text)) = client.next().await.transpose()? else {
        return Err("missing client response frame".into());
    };
    assert!(!client_text.contains(SECRET));
    assert!(client_text.contains("[REDACTED]"));

    proxy_stop.cancel();
    Ok(())
}

#[tokio::test]
async fn websocket_rejects_opaque_text_without_forwarding_it()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_address = listener.local_addr()?;
    let (capture_tx, mut capture_rx) = mpsc::channel(1);
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut socket) = accept_async(stream).await else {
            return;
        };
        if let Some(Ok(WsMessage::Text(text))) = socket.next().await {
            let _ = capture_tx.send(text.to_string()).await;
        }
    });
    let (proxy, proxy_stop) = spawn_proxy(upstream_address, Provider::OpenAi).await?;
    let websocket_url = proxy.replacen("http://", "ws://", 1) + "/openai/v1/responses";
    let (mut client, _) = connect_async(websocket_url).await?;

    client.send(WsMessage::Text(SECRET.into())).await?;
    let forwarded = tokio::time::timeout(Duration::from_millis(250), capture_rx.recv()).await;
    assert!(!matches!(forwarded, Ok(Some(_))));

    proxy_stop.cancel();
    Ok(())
}

#[tokio::test]
async fn websocket_loop_marker_is_rejected_before_connecting_upstream()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_address = listener.local_addr()?;
    let (proxy, proxy_stop) = spawn_proxy(upstream_address, Provider::OpenAi).await?;
    let websocket_url = proxy.replacen("http://", "ws://", 1) + "/openai/v1/responses";
    let mut request = websocket_url.into_client_request()?;
    request
        .headers_mut()
        .insert("x-blindfold-proxy-hop", HeaderValue::from_static("1"));

    let Err(error) = connect_async(request).await else {
        return Err("loop-marked WebSocket unexpectedly connected".into());
    };
    let tokio_tungstenite::tungstenite::Error::Http(response) = error else {
        return Err("loop-marked WebSocket returned an unexpected error".into());
    };
    assert_eq!(response.status(), StatusCode::LOOP_DETECTED);
    assert!(
        tokio::time::timeout(Duration::from_millis(250), listener.accept())
            .await
            .is_err()
    );

    proxy_stop.cancel();
    Ok(())
}

#[tokio::test]
async fn sensitive_json_request_key_fails_closed_without_trace_or_upstream_leak()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let traces = TraceCapture::default();
    let (upstream, upstream_stop) = spawn_upstream(capture.clone(), openai_response()).await?;
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

    let response = reqwest::Client::new()
        .post(format!("http://{address}/openai/v1/chat/completions"))
        .header(CONTENT_TYPE, "application/json")
        .body(format!(r#"{{"{SECRET}":"value"}}"#))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!response.text().await?.contains(SECRET));
    assert!(
        capture
            .bodies
            .lock()
            .map_err(|_| "capture poisoned")?
            .is_empty()
    );
    let records = traces
        .records
        .lock()
        .map_err(|_| "trace capture poisoned")?;
    assert_eq!(records.len(), 1);
    assert!(!records[0].to_json()?.contains(SECRET));

    proxy_stop.cancel();
    let _ = upstream_stop.send(());
    Ok(())
}

#[tokio::test]
async fn sensitive_json_response_key_fails_closed_without_client_leak()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let response = json_response(&serde_json::json!({ (SECRET): "value" }))?;
    let (upstream, upstream_stop) = spawn_upstream(capture, response).await?;
    let (proxy, proxy_stop) = spawn_proxy(upstream, Provider::OpenAi).await?;

    let response = reqwest::Client::new()
        .post(format!("{proxy}/openai/v1/chat/completions"))
        .header(CONTENT_TYPE, "application/json")
        .body("{}")
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.text().await?;
    assert!(!body.contains(SECRET));
    assert!(body.contains("invalid_json"));

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
async fn rejects_sse_requests_before_the_upstream() -> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let (upstream, upstream_stop) = spawn_upstream(capture.clone(), openai_response()).await?;
    let (proxy, proxy_stop) = spawn_proxy(upstream, Provider::Anthropic).await?;

    let response = reqwest::Client::new()
        .post(format!("{proxy}/anthropic/v1/messages"))
        .header(CONTENT_TYPE, "text/event-stream")
        .body(format!("data: {{\"text\":\"{SECRET}\"}}\n\n"))
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
async fn sanitizes_openai_chat_completion_sse_and_preserves_done()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let response = streamed_response(
        [Bytes::from(format!(
            "data: {{\"id\":\"chunk-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"echo {SECRET}\"}}}}]}}\n\ndata: [DONE]\n\n"
        ))],
        "text/event-stream",
    );
    let (upstream, upstream_stop) = spawn_upstream(capture, response).await?;
    let (proxy, proxy_stop) = spawn_proxy(upstream, Provider::OpenAi).await?;

    let response = reqwest::Client::new()
        .post(format!("{proxy}/openai/v1/chat/completions"))
        .header(CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(&serde_json::json!({
            "model": "openai/gpt-4o-mini",
            "messages": [
                {"role": "system", "content": "safe system context"},
                {"role": "user", "content": "safe prompt"}
            ],
            "stream": true,
            "tool_choice": "auto",
            "tools": [{
                "type": "function",
                "function": {
                    "name": "read",
                    "description": "read a file",
                    "parameters": {"type": "object"}
                }
            }]
        }))?)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(CONTENT_TYPE),
        Some(&HeaderValue::from_static("text/event-stream"))
    );
    let body = response.text().await?;
    assert!(!body.contains(SECRET));
    assert!(body.contains("echo [REDACTED]"));
    assert!(body.ends_with("data: [DONE]\n\n"));

    proxy_stop.cancel();
    let _ = upstream_stop.send(());
    Ok(())
}

#[tokio::test]
async fn rejects_opaque_openai_chat_completion_sse() -> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let response = streamed_response(
        [Bytes::from(format!("data: opaque-{SECRET}\n\n"))],
        "text/event-stream",
    );
    let (upstream, upstream_stop) = spawn_upstream(capture, response).await?;
    let (proxy, proxy_stop) = spawn_proxy(upstream, Provider::OpenAi).await?;

    let response = reqwest::Client::new()
        .post(format!("{proxy}/openai/v1/chat/completions"))
        .header(CONTENT_TYPE, "application/json")
        .body("{}")
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.text().await?;
    assert!(!body.contains(SECRET));
    assert!(body.contains("invalid_json"));

    proxy_stop.cancel();
    let _ = upstream_stop.send(());
    Ok(())
}

#[tokio::test]
async fn rejects_openai_sse_on_unsupported_path() -> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let response = streamed_response(
        [Bytes::from(format!("data: {{\"delta\":\"{SECRET}\"}}\n\n"))],
        "text/event-stream",
    );
    let (upstream, upstream_stop) = spawn_upstream(capture, response).await?;
    let (proxy, proxy_stop) = spawn_proxy(upstream, Provider::OpenAi).await?;

    let response = reqwest::Client::new()
        .post(format!("{proxy}/openai/v1/messages"))
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
async fn trusted_gateway_accepts_one_proxy_hop_and_advances_the_marker()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let (upstream, upstream_stop) = spawn_upstream(capture.clone(), openai_response()).await?;
    let config = proxy_config_with_trusted_proxy_hop(upstream, Provider::OpenAi)?;
    let (proxy, proxy_stop) = spawn_proxy_with_config(config).await?;

    reqwest::Client::new()
        .post(format!("{proxy}/openai/v1/chat/completions"))
        .header("x-blindfold-proxy-hop", "1")
        .header(CONTENT_TYPE, "application/json")
        .body("{}")
        .send()
        .await?
        .error_for_status()?;

    let headers = capture.headers.lock().map_err(|_| "capture poisoned")?;
    assert_eq!(headers.len(), 1);
    assert_eq!(
        headers[0]
            .get("x-blindfold-proxy-hop")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );

    proxy_stop.cancel();
    let _ = upstream_stop.send(());
    Ok(())
}

#[tokio::test]
async fn trusted_gateway_rejects_a_second_proxy_hop_before_upstream()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let (upstream, upstream_stop) = spawn_upstream(capture.clone(), openai_response()).await?;
    let config = proxy_config_with_trusted_proxy_hop(upstream, Provider::OpenAi)?;
    let (proxy, proxy_stop) = spawn_proxy_with_config(config).await?;

    let response = reqwest::Client::new()
        .post(format!("{proxy}/openai/v1/chat/completions"))
        .header("x-blindfold-proxy-hop", "2")
        .header(CONTENT_TYPE, "application/json")
        .body("{}")
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::LOOP_DETECTED);
    assert!(
        capture
            .headers
            .lock()
            .map_err(|_| "capture poisoned")?
            .is_empty()
    );

    proxy_stop.cancel();
    let _ = upstream_stop.send(());
    Ok(())
}

#[test]
fn trusted_proxy_hop_requires_gateway_credential() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = Config::default();
    config.upstreams.push(
        Upstream::new("openai", "https://api.example.test", Provider::OpenAi)?
            .with_trusted_proxy_hop(),
    );
    let sanitizer = Arc::new(ExactValueSanitizer::new(SECRET, "[REDACTED]")?);
    let Err(error) = Proxy::new(config, sanitizer) else {
        return Err("uncredentialed trusted proxy hop was accepted".into());
    };
    assert_eq!(error, ConfigError::UncredentialedTrustedProxyHop);
    Ok(())
}

#[tokio::test]
async fn rejects_websocket_upgrade_without_forwarding_body()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let (upstream, upstream_stop) = spawn_upstream(capture.clone(), openai_response()).await?;
    let (proxy, proxy_stop) = spawn_proxy(upstream, Provider::OpenAi).await?;

    let response = reqwest::Client::new()
        .post(format!("{proxy}/openai/v1/responses"))
        .header("connection", "keep-alive, Upgrade")
        .header("upgrade", "websocket")
        .header(CONTENT_TYPE, "application/json")
        .body(format!(r#"{{"input":"{SECRET}"}}"#))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.text().await?;
    assert!(!body.contains(SECRET));
    assert!(body.contains("unsupported_transport"));
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
async fn strips_untrusted_upstream_response_headers() -> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let response = Response::builder()
        .header(CONTENT_TYPE, "application/problem+json; charset=utf-8")
        .header("x-upstream-secret", SECRET)
        .body(Body::from(r#"{"error":"safe"}"#))?;
    let (upstream, upstream_stop) = spawn_upstream(capture, response).await?;
    let (proxy, proxy_stop) = spawn_proxy(upstream, Provider::OpenAi).await?;

    let response = reqwest::Client::new()
        .post(format!("{proxy}/openai/v1/chat/completions"))
        .header(CONTENT_TYPE, "application/json")
        .body("{}")
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    assert!(!response.headers().contains_key("x-upstream-secret"));

    proxy_stop.cancel();
    let _ = upstream_stop.send(());
    Ok(())
}

#[tokio::test]
async fn rejects_empty_bodies_with_unsupported_content_types()
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
        ..Config::default()
    };
    config.upstreams.push(Upstream::new(
        route_name,
        format!("http://{upstream_addr}"),
        provider,
    )?);
    Ok(config)
}

fn proxy_config_with_gateway_credential(
    upstream_addr: std::net::SocketAddr,
    provider: Provider,
    credential: &str,
) -> Result<Config, Box<dyn std::error::Error>> {
    let route_name = match provider {
        Provider::OpenAi => "openai",
        Provider::Anthropic => "anthropic",
    };
    let mut config = Config {
        request_timeout: Duration::from_secs(5),
        ..Config::default()
    };
    config.upstreams.push(
        Upstream::new(route_name, format!("http://{upstream_addr}"), provider)?
            .with_gateway_credential(credential)?,
    );
    Ok(config)
}

fn proxy_config_with_trusted_proxy_hop(
    upstream_addr: std::net::SocketAddr,
    provider: Provider,
) -> Result<Config, Box<dyn std::error::Error>> {
    let route_name = match provider {
        Provider::OpenAi => "openai",
        Provider::Anthropic => "anthropic",
    };
    let mut config = Config {
        request_timeout: Duration::from_secs(5),
        ..Config::default()
    };
    config.upstreams.push(
        Upstream::new(route_name, format!("http://{upstream_addr}"), provider)?
            .with_gateway_credential(TRUSTED_CREDENTIAL)?
            .with_trusted_proxy_hop(),
    );
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
    let (parts, body) = request.into_parts();
    if let Ok(mut headers) = state.capture.headers.lock() {
        headers.push(parts.headers);
    }
    let Ok(body) = to_bytes(body, 1024 * 1024).await else {
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
        "event: content_block_delta\r\ndata: {{\"delta\":{{\"type\":\"text_delta\",\"text\":\"{}",
        &SECRET[..7]
    );
    let second = format!("{}\"}}}}\r\n\r\n", &SECRET[7..]);
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
