//! The one seam every HTTP request of the engine goes through.
//!
//! The engine builds a [`Request`] and hands it to a [`Transport`]. Nothing
//! else in the engine opens a connection, sleeps or reads a clock. The native
//! build supplies [`ReqwestTransport`]; a WebAssembly host supplies its own,
//! over `fetch` and its own timers, because `std::time::Instant` and every
//! thread-backed timer panic or fail on `wasm32-unknown-unknown`.
//!
//! A transport is a carrier, not a decision maker. It sends the request as
//! built, honours `follow_redirects`, `timeout` and `max_response_bytes`, and
//! reports what came back. Every judgement about the answer stays in the
//! engine, so one audit reads the same through either transport.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use zeroize::Zeroizing;

#[cfg(feature = "native")]
mod reqwest_transport;
#[cfg(feature = "native")]
pub use reqwest_transport::ReqwestTransport;

/// A transport's pending answer.
///
/// Not `Send`: a WebAssembly host's futures are JavaScript promises, and the
/// engine never moves a request between threads.
pub type TransportFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// The bounds a transport carries, by target.
///
/// Natively a transport is `Send + Sync`, so a client that holds one can move
/// to a worker thread. A WebAssembly host's transport holds JavaScript values,
/// which are neither, and there is only one thread.
#[cfg(not(target_arch = "wasm32"))]
pub trait TransportBounds: Send + Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync + ?Sized> TransportBounds for T {}

/// The bounds a transport carries, by target.
#[cfg(target_arch = "wasm32")]
pub trait TransportBounds {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> TransportBounds for T {}

/// The methods the engine sends.
///
/// `POST` and `DELETE` belong to central mode alone: an Azure token, a Key
/// Vault sign, minting and revoking the installation token. No audit request
/// writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// A read.
    Get,
    /// A request with a body.
    Post,
    /// Revoking a token.
    Delete,
}

impl Method {
    /// The method's name on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Delete => "DELETE",
        }
    }
}

/// One request, as the engine built it.
///
/// Header values and the body may carry a credential, so both are overwritten
/// when the request is dropped, and `Debug` shows only the method and URL.
pub struct Request {
    /// The method.
    pub method: Method,
    /// The absolute URL. The engine never puts a credential in one.
    pub url: String,
    /// Header names, lowercase, and their values.
    pub headers: Vec<(String, Zeroizing<String>)>,
    /// The body, for a `POST`.
    pub body: Option<Zeroizing<Vec<u8>>>,
    /// Whether a redirect may be followed. When false, a redirect is returned
    /// as the answer.
    pub follow_redirects: bool,
    /// How long the whole request, body included, may take.
    pub timeout: Duration,
    /// The largest body the transport may read. A longer one is abandoned
    /// with [`FailureKind::TooLarge`] rather than read whole.
    pub max_response_bytes: usize,
}

impl Request {
    /// A request with no headers and no body.
    #[must_use]
    pub fn new(method: Method, url: impl Into<String>) -> Self {
        Self {
            method,
            url: url.into(),
            headers: Vec::new(),
            body: None,
            follow_redirects: false,
            timeout: Duration::from_secs(30),
            max_response_bytes: 0,
        }
    }

    /// Add a header. The name is lowercased.
    #[must_use]
    pub fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers
            .push((name.to_ascii_lowercase(), Zeroizing::new(value.into())));
        self
    }

    /// Add `Authorization: Bearer <token>`.
    #[must_use]
    pub fn bearer(self, token: &str) -> Self {
        self.header("authorization", format!("Bearer {token}"))
    }

    /// Set the body.
    #[must_use]
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(Zeroizing::new(body.into()));
        self
    }

    /// The value of a header, by lowercase name.
    #[must_use]
    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(found, _)| found == name)
            .map(|(_, value)| value.as_str())
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Headers and body are deliberately absent: they carry credentials.
        formatter
            .debug_struct("Request")
            .field("method", &self.method)
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

/// One answer.
///
/// The body may carry a credential (a minted token, an access token), so it
/// is overwritten when the answer is dropped.
pub struct Response {
    /// The HTTP status.
    pub status: u16,
    /// Every header field, in the order received. A repeated field appears
    /// once per repetition. Names may be in any case.
    pub headers: Vec<(String, String)>,
    /// The body, at most the request's `max_response_bytes`.
    pub body: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Response {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Response")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// How a request failed before an answer was complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// The request's `timeout` passed.
    Timeout,
    /// No connection could be made.
    Connect,
    /// The body passed `max_response_bytes` and was abandoned.
    TooLarge,
    /// The host's clock or timer gave a value the engine cannot use: not a
    /// number, negative, out of range, or earlier than one it gave before.
    Clock,
    /// Anything else.
    Other,
}

/// A request that produced no complete answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportError {
    /// What kind of failure.
    pub kind: FailureKind,
    /// The transport's description. It may name the URL, and never carries a
    /// header value or a body.
    pub detail: String,
}

impl TransportError {
    /// A failure of `kind`.
    #[must_use]
    pub fn new(kind: FailureKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for TransportError {}

/// Where the engine's requests, waits and clock readings go.
pub trait Transport: TransportBounds {
    /// Send one request and read its answer.
    ///
    /// # Errors
    ///
    /// Returns a [`TransportError`] when no complete answer arrived. An HTTP
    /// error status is an answer, not an error.
    fn send(&self, request: Request) -> TransportFuture<'_, Result<Response, TransportError>>;

    /// Wait for `duration`. Used only between rate-limited retries.
    ///
    /// # Errors
    ///
    /// Returns a [`FailureKind::Clock`] error when the timer cannot wait.
    fn sleep(&self, duration: Duration) -> TransportFuture<'_, Result<(), TransportError>>;

    /// Time since an arbitrary origin that never moves backwards. Budgets are
    /// measured on it.
    ///
    /// # Errors
    ///
    /// Returns a [`FailureKind::Clock`] error when the clock gives no usable
    /// reading. The engine stops rather than guess at a budget.
    fn monotonic(&self) -> Result<Duration, TransportError>;

    /// Time since the Unix epoch. Rate-limit resets and the App's JSON Web
    /// Token are stated on it.
    ///
    /// # Errors
    ///
    /// Returns a [`FailureKind::Clock`] error when the clock gives no usable
    /// reading.
    fn unix_time(&self) -> Result<Duration, TransportError>;
}
