//! The native transport: reqwest, tokio's timer and the system clock.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use super::{FailureKind, Method, Request, Response, Transport, TransportError, TransportFuture};

/// The native [`Transport`].
///
/// It keeps two connection pools, one that follows redirects and one that
/// does not, because reqwest fixes the redirect policy per client and the
/// engine decides it per request.
#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    following: reqwest::Client,
    refusing: reqwest::Client,
    origin: Instant,
}

impl ReqwestTransport {
    /// Build the transport, with a connection timeout for every request.
    ///
    /// # Errors
    ///
    /// Returns an error when the HTTP stack cannot be built.
    pub fn new(connect_timeout: Duration) -> Result<Self, TransportError> {
        let build = |policy: reqwest::redirect::Policy| {
            reqwest::Client::builder()
                // Audits are bursty, and the interactive session may sit idle
                // longer than GitHub keeps a connection alive. Retain
                // connections within a burst, but drop them across the longer
                // idle stretches.
                .pool_idle_timeout(Duration::from_secs(5))
                // Without these, a server that accepts a connection and never
                // finishes the body hangs the audit forever. The whole-request
                // timeout is set per request.
                .connect_timeout(connect_timeout)
                .redirect(policy)
                .build()
                .map_err(|error| TransportError::new(FailureKind::Other, error.to_string()))
        };
        Ok(Self {
            following: build(reqwest::redirect::Policy::default())?,
            refusing: build(reqwest::redirect::Policy::none())?,
            origin: Instant::now(),
        })
    }

    async fn perform(&self, mut request: Request) -> Result<Response, TransportError> {
        let client = if request.follow_redirects {
            &self.following
        } else {
            &self.refusing
        };
        let method = match request.method {
            Method::Get => reqwest::Method::GET,
            Method::Post => reqwest::Method::POST,
            Method::Delete => reqwest::Method::DELETE,
        };
        let mut builder = client
            .request(method, request.url.as_str())
            .timeout(request.timeout);
        for (name, value) in &request.headers {
            let mut value =
                reqwest::header::HeaderValue::from_str(value.as_str()).map_err(|_| {
                    TransportError::new(FailureKind::Other, "a header value is not valid")
                })?;
            // As reqwest's own bearer_auth does: a credential header is kept
            // out of reqwest's debug output.
            value.set_sensitive(name == "authorization");
            builder = builder.header(name.as_str(), value);
        }
        if let Some(body) = request.body.take() {
            builder = builder.body(body.to_vec());
        }
        let mut response = builder.send().await.map_err(|error| failure(&error))?;

        let status = response.status().as_u16();
        // Multi-valued, because HTTP lets a field repeat and a security
        // decision made from whichever repetition survived a map insert is
        // not a decision.
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect();

        // Chunked rather than buffered whole, so an endless or enormous body
        // is abandoned at the limit instead of being materialised first.
        let mut body = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(|error| failure(&error))? {
            if body.len() + chunk.len() > request.max_response_bytes {
                return Err(TransportError::new(
                    FailureKind::TooLarge,
                    format!(
                        "the response exceeded the {} byte limit and was abandoned",
                        request.max_response_bytes
                    ),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Response {
            status,
            headers,
            body,
        })
    }
}

impl Transport for ReqwestTransport {
    fn send(&self, request: Request) -> TransportFuture<'_, Result<Response, TransportError>> {
        Box::pin(self.perform(request))
    }

    fn sleep(&self, duration: Duration) -> TransportFuture<'_, ()> {
        Box::pin(tokio::time::sleep(duration))
    }

    fn monotonic(&self) -> Duration {
        self.origin.elapsed()
    }

    fn unix_time(&self) -> Duration {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
    }
}

fn failure(error: &reqwest::Error) -> TransportError {
    let kind = if error.is_timeout() {
        FailureKind::Timeout
    } else if error.is_connect() {
        FailureKind::Connect
    } else {
        FailureKind::Other
    };
    TransportError::new(kind, error.to_string())
}
