//! The WebAssembly exports and the host's transport.
//!
//! The host passes an object with three methods (see `AirlockHost` in the
//! TypeScript section below). The module makes no request, waits for nothing
//! and reads no clock except through it, so the same module runs under
//! Node, in the JavaScript action, and in a Cloudflare Worker.

use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use airlock_core::transport::{
    FailureKind, Request, Response, Transport, TransportError, TransportFuture,
};
use js_sys::{Array, Object, Promise, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{future_to_promise, JsFuture};
use zeroize::Zeroizing;

use crate::engine::{self, EngineError};

#[wasm_bindgen(typescript_custom_section)]
const HOST_INTERFACE: &'static str = r#"
/** One request, as the engine built it. */
export interface AirlockRequest {
  method: "GET" | "POST" | "DELETE";
  url: string;
  /** Lowercase names. `authorization` carries a credential: never log it. */
  headers: [string, string][];
  /** Present for a POST. It may carry a credential: never log it. */
  body?: Uint8Array;
  /** "manual" returns a redirect as the answer. */
  redirect: "follow" | "manual";
  /** The whole request, body included, may take this long. */
  timeoutMs: number;
  /** Abandon a longer body, rejecting with a `TooLargeError`. */
  maxResponseBytes: number;
}

/** One answer. An HTTP error status is an answer, not a rejection. */
export interface AirlockResponse {
  status: number;
  /** Every field, once per repetition. */
  headers: [string, string][];
  body: Uint8Array;
}

/**
 * What the module runs on. `fetch` rejects with an error whose `name` is
 * `TimeoutError`, `ConnectError` or `TooLargeError` when that is what
 * happened, and any other name otherwise.
 */
export interface AirlockHost {
  fetch(request: AirlockRequest): Promise<AirlockResponse>;
  sleep(ms: number): Promise<void>;
  /** Milliseconds since the Unix epoch. */
  now(): number;
}
"#;

#[wasm_bindgen]
extern "C" {
    /// The host object.
    #[wasm_bindgen(typescript_type = "AirlockHost")]
    pub type Host;

    // Each returns a bare value, checked here, rather than a type
    // wasm-bindgen would cast to unchecked: a host is untrusted input, and a
    // wrong type must be an error, not a trap or a JavaScript exception
    // thrown through the module.
    #[wasm_bindgen(method, catch)]
    fn fetch(this: &Host, request: &JsValue) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch)]
    fn sleep(this: &Host, ms: f64) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch)]
    fn now(this: &Host) -> Result<JsValue, JsValue>;
}

/// The latest time a JavaScript `Date` can hold, in milliseconds since the
/// epoch. A host clock beyond it is not a clock.
const MAX_CLOCK_MS: f64 = 8.64e15;

fn clock_failure(detail: &str) -> TransportError {
    TransportError::new(FailureKind::Clock, detail)
}

/// The host's [`Transport`].
struct HostTransport {
    host: Host,
    /// The latest clock reading. A reading earlier than it is refused, so a
    /// clock that steps back cannot hand budget back.
    latest: Cell<u64>,
}

impl HostTransport {
    fn new(host: Host) -> Self {
        Self {
            host,
            latest: Cell::new(0),
        }
    }

    /// One reading of the host's clock, in whole milliseconds, checked.
    ///
    /// The host's own message is not kept: it is the host's text.
    fn read_clock(&self) -> Result<u64, TransportError> {
        let value = self
            .host
            .now()
            .map_err(|_| clock_failure("the host's now() threw"))?;
        let ms = value
            .as_f64()
            .ok_or_else(|| clock_failure("the host's now() did not return a number"))?;
        if !ms.is_finite() || !(0.0..=MAX_CLOCK_MS).contains(&ms) {
            return Err(clock_failure(
                "the host's now() returned a time outside 1970 to the year 275760",
            ));
        }
        // In range, so the cast neither truncates past u64 nor wraps.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Ok(ms.floor() as u64)
    }

    async fn perform(&self, request: Request) -> Result<Response, TransportError> {
        let max = request.max_response_bytes;
        let value = request_object(&request).map_err(|_| {
            TransportError::new(FailureKind::Other, "the request could not be built")
        })?;
        drop(request);
        let answer = self.host.fetch(&value).map_err(|error| rejection(&error))?;
        // A host that answers with a plain value rather than a promise is
        // read as having resolved to it.
        let answer = JsFuture::from(Promise::resolve(&answer))
            .await
            .map_err(|error| rejection(&error))?;
        response_from(&answer, max)
    }
}

fn get(value: &JsValue, key: &str) -> Result<JsValue, TransportError> {
    Reflect::get(value, &JsValue::from_str(key)).map_err(|_| malformed(key))
}

fn malformed(what: &str) -> TransportError {
    TransportError::new(
        FailureKind::Other,
        format!("the host's answer has no readable `{what}`"),
    )
}

fn request_object(request: &Request) -> Result<JsValue, JsValue> {
    let object = Object::new();
    let set = |key: &str, value: &JsValue| Reflect::set(&object, &JsValue::from_str(key), value);
    set("method", &JsValue::from_str(request.method.as_str()))?;
    set("url", &JsValue::from_str(&request.url))?;
    let headers = Array::new();
    for (name, value) in &request.headers {
        headers.push(&Array::of2(
            &JsValue::from_str(name),
            &JsValue::from_str(value),
        ));
    }
    set("headers", &headers)?;
    if let Some(body) = &request.body {
        set("body", &Uint8Array::from(body.as_slice()))?;
    }
    set(
        "redirect",
        &JsValue::from_str(if request.follow_redirects {
            "follow"
        } else {
            "manual"
        }),
    )?;
    #[allow(clippy::cast_precision_loss)]
    let timeout = request.timeout.as_millis() as f64;
    set("timeoutMs", &JsValue::from_f64(timeout))?;
    #[allow(clippy::cast_precision_loss)]
    let max = request.max_response_bytes as f64;
    set("maxResponseBytes", &JsValue::from_f64(max))?;
    Ok(object.into())
}

fn response_from(answer: &JsValue, max: usize) -> Result<Response, TransportError> {
    let status = get(answer, "status")?
        .as_f64()
        .filter(|status| status.fract() == 0.0 && (100.0..=599.0).contains(status))
        .ok_or_else(|| malformed("status"))?;
    let mut headers = Vec::new();
    let fields = get(answer, "headers")?;
    if !Array::is_array(&fields) {
        return Err(malformed("headers"));
    }
    for field in Array::from(&fields).iter() {
        if !Array::is_array(&field) {
            return Err(malformed("headers"));
        }
        let field = Array::from(&field);
        match (field.get(0).as_string(), field.get(1).as_string()) {
            (Some(name), Some(value)) if field.length() == 2 => headers.push((name, value)),
            _ => return Err(malformed("headers")),
        }
    }
    let body = get(answer, "body")?;
    if !body.is_instance_of::<Uint8Array>() {
        return Err(malformed("body"));
    }
    let body = Uint8Array::from(body);
    // The host was told the limit; the engine holds it too, so a host that
    // ignores it cannot hand over more.
    if body.length() as usize > max {
        return Err(TransportError::new(
            FailureKind::TooLarge,
            format!("the response exceeded the {max} byte limit and was abandoned"),
        ));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let status = status as u16;
    Ok(Response {
        status,
        headers,
        body: Zeroizing::new(body.to_vec()),
    })
}

/// The kind a host's rejection names, and its message.
fn rejection(error: &JsValue) -> TransportError {
    let text = |key: &str| {
        Reflect::get(error, &JsValue::from_str(key))
            .ok()
            .and_then(|value| value.as_string())
    };
    let kind = match text("name").as_deref() {
        Some("TimeoutError") => FailureKind::Timeout,
        Some("ConnectError") => FailureKind::Connect,
        Some("TooLargeError") => FailureKind::TooLarge,
        _ => FailureKind::Other,
    };
    let detail = text("message")
        .or_else(|| error.as_string())
        .unwrap_or_else(|| "the host's fetch failed".to_owned());
    TransportError::new(kind, detail)
}

impl Transport for HostTransport {
    fn send(&self, request: Request) -> TransportFuture<'_, Result<Response, TransportError>> {
        Box::pin(self.perform(request))
    }

    fn sleep(&self, duration: Duration) -> TransportFuture<'_, Result<(), TransportError>> {
        #[allow(clippy::cast_precision_loss)]
        let ms = duration.as_millis() as f64;
        let started = self.host.sleep(ms);
        Box::pin(async move {
            let value = started.map_err(|_| clock_failure("the host's sleep() threw"))?;
            JsFuture::from(Promise::resolve(&value))
                .await
                .map(|_| ())
                .map_err(|_| clock_failure("the host's sleep() rejected"))
        })
    }

    fn monotonic(&self) -> Result<Duration, TransportError> {
        let now = self.read_clock()?;
        if now < self.latest.get() {
            return Err(clock_failure(
                "the host's now() moved backwards, so the audit budget cannot be measured",
            ));
        }
        self.latest.set(now);
        Ok(Duration::from_millis(now))
    }

    fn unix_time(&self) -> Result<Duration, TransportError> {
        self.read_clock().map(Duration::from_millis)
    }
}

fn transport(host: Host) -> Arc<dyn Transport> {
    #[allow(clippy::arc_with_non_send_sync)]
    Arc::new(HostTransport::new(host))
}

/// An [`EngineError`] as a JavaScript `Error`, with `kind`, and for central
/// mode `step`, `status` and `code`.
fn js_error(error: &EngineError) -> JsValue {
    let value = js_sys::Error::new(&error.message);
    value.set_name("AirlockError");
    let set = |key: &str, field: JsValue| {
        let _ = Reflect::set(&value, &JsValue::from_str(key), &field);
    };
    set("kind", JsValue::from_str(error.kind));
    if let Some(step) = error.step {
        set("step", JsValue::from_str(step));
    }
    if let Some(status) = error.status {
        set("status", JsValue::from_f64(f64::from(status)));
    }
    if let Some(code) = &error.code {
        set("code", JsValue::from_str(code));
    }
    value.into()
}

/// Audit one repository with a token, and resolve to its findings document
/// as JSON.
///
/// `request` is JSON: `{ token, owner, repo, policy?, githubApi? }`. The
/// token is verified before any other request, as on every surface.
///
/// # Errors
///
/// Rejects with an `AirlockError`.
#[wasm_bindgen]
pub async fn audit(host: Host, request: String) -> Result<String, JsValue> {
    let request = Zeroizing::new(request);
    let parsed = engine::AuditRequest::parse(&request).map_err(|error| js_error(&error))?;
    drop(request);
    engine::audit(transport(host), &parsed)
        .await
        .map_err(|error| js_error(&error))
}

/// A central run signed in as Airlock Safe.
///
/// Holds Safe's installation token inside the module; no method returns it.
/// Call `revoke()` when the run ends, then `free()`, which overwrites it.
#[wasm_bindgen]
pub struct CentralSession {
    inner: Rc<engine::Session>,
}

#[wasm_bindgen]
impl CentralSession {
    /// Sign in as Airlock Safe through Key Vault with the host's Entra
    /// credential.
    ///
    /// `request` is JSON: `{ owner, appId, keyName, installationRepositories,
    /// vaultUrl, azureTenantId, azureClientId, credential: { kind, value },
    /// githubApi?, azureLogin? }`, where `kind` is `client-secret` or
    /// `client-assertion`.
    ///
    /// # Errors
    ///
    /// Rejects with an `AirlockError` whose `step` names the step that
    /// refused.
    #[wasm_bindgen(js_name = signIn)]
    pub async fn sign_in(host: Host, request: String) -> Result<CentralSession, JsValue> {
        let request = Zeroizing::new(request);
        let parsed = engine::CentralRequest::parse(&request).map_err(|error| js_error(&error))?;
        drop(request);
        let session = engine::sign_in(transport(host), &parsed)
            .await
            .map_err(|error| js_error(&error))?;
        Ok(Self {
            inner: Rc::new(session),
        })
    }

    /// What the session's credential is, as JSON. No token is in it.
    ///
    /// # Errors
    ///
    /// Throws when the grant cannot be rendered.
    pub fn grant(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner.grant())
            .map_err(|error| JsValue::from_str(&error.to_string()))
    }

    /// Audit one repository of the owner, resolving to its findings
    /// document as JSON.
    #[wasm_bindgen(js_name = auditRepository)]
    pub fn audit_repository(&self, repo: String, policy: Option<String>) -> Promise {
        let inner = Rc::clone(&self.inner);
        future_to_promise(async move {
            inner
                .audit_repository(&repo, policy.as_deref())
                .await
                .map(|report| JsValue::from_str(&report))
                .map_err(|error| js_error(&error))
        })
    }

    /// Audit every repository the installation reaches, resolving to the
    /// central report as JSON.
    #[wasm_bindgen(js_name = auditInstallation)]
    pub fn audit_installation(&self, policy: Option<String>) -> Promise {
        let inner = Rc::clone(&self.inner);
        future_to_promise(async move {
            inner
                .audit_installation(policy.as_deref())
                .await
                .map(|report| JsValue::from_str(&report))
                .map_err(|error| js_error(&error))
        })
    }

    /// Revoke the installation token.
    pub fn revoke(&self) -> Promise {
        let inner = Rc::clone(&self.inner);
        future_to_promise(async move {
            inner
                .revoke()
                .await
                .map(|()| JsValue::UNDEFINED)
                .map_err(|error| js_error(&error))
        })
    }
}
