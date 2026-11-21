//! Record the GitHub responses of one audit, for the parity test.
//!
//! ```sh
//! AIRLOCK_RECORD_TOKEN=... cargo run -p airlock-wasm --example record_audit -- \
//!     wyrd-company airlock 'wyrd-company/airlock:docs/examples/org-airlock.yml@<sha>' \
//!     crates/wasm/tests/fixtures/audit-airlock.json
//! ```
//!
//! The engine runs with the placeholder token the parity test presents, so
//! the recording holds the requests that token makes. The token's
//! verification (`GET /user/installations`) is answered here, from a canned
//! Airlock Safe installation with read permissions; every other request goes
//! to GitHub with `AIRLOCK_RECORD_TOKEN` in place of the placeholder. Any
//! token that can read the repository will do.
//!
//! The recording keeps no request header and only the response headers the
//! engine reads. It is refused, and nothing is written, when any part of it
//! contains the recording token or anything shaped like a GitHub token.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use airlock_core::limits::Limits;
use airlock_core::transport::{
    Request, ReqwestTransport, Response, Transport, TransportError, TransportFuture,
};
use airlock_wasm::engine::{self, AuditRequest};
use serde_json::{json, Value};
use zeroize::Zeroizing;

/// The token the parity test presents. Never a credential.
const PLACEHOLDER: &str = "ghu_PLACEHOLDER";

/// The GitHub API root the recording is made against.
const GITHUB_API: &str = "https://api.github.com";

/// The response headers the engine reads.
const KEPT_HEADERS: &[&str] = &[
    "content-type",
    "date",
    "link",
    "location",
    "retry-after",
    "x-accepted-github-permissions",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-ratelimit-resource",
];

struct Recorder {
    inner: ReqwestTransport,
    token: Zeroizing<String>,
    exchanges: Mutex<Vec<Value>>,
}

fn path_of(url: &str) -> String {
    url.strip_prefix(GITHUB_API).unwrap_or(url).to_owned()
}

impl Recorder {
    async fn perform(&self, mut request: Request) -> Result<Response, TransportError> {
        assert_eq!(
            request.header_value("authorization"),
            Some(format!("Bearer {PLACEHOLDER}").as_str()),
            "the engine sent another credential"
        );
        let path = path_of(&request.url);
        let method = request.method.as_str();

        let response = if path.starts_with("/user/installations") {
            Response {
                status: 200,
                headers: vec![(
                    "content-type".to_owned(),
                    "application/json; charset=utf-8".to_owned(),
                )],
                body: Zeroizing::new(canned_installations().to_string().into_bytes()),
            }
        } else {
            for (name, value) in &mut request.headers {
                if name == "authorization" {
                    *value = Zeroizing::new(format!("Bearer {}", self.token.as_str()));
                }
            }
            self.inner.send(request).await?
        };

        let headers: Vec<Value> = response
            .headers
            .iter()
            .filter(|(name, _)| KEPT_HEADERS.contains(&name.to_ascii_lowercase().as_str()))
            .map(|(name, value)| json!([name.to_ascii_lowercase(), value]))
            .collect();
        let body = String::from_utf8(response.body.to_vec()).expect("GitHub answers in UTF-8");
        self.exchanges.lock().expect("one thread").push(json!({
            "method": method,
            "path": path,
            "status": response.status,
            "headers": headers,
            "body": body,
        }));
        Ok(response)
    }
}

impl Transport for Recorder {
    fn send(&self, request: Request) -> TransportFuture<'_, Result<Response, TransportError>> {
        Box::pin(self.perform(request))
    }

    fn sleep(&self, duration: Duration) -> TransportFuture<'_, ()> {
        self.inner.sleep(duration)
    }

    fn monotonic(&self) -> Duration {
        self.inner.monotonic()
    }

    fn unix_time(&self) -> Duration {
        self.inner.unix_time()
    }
}

/// What a read-only Airlock Safe user token's verification sees.
fn canned_installations() -> Value {
    json!({
        "total_count": 1,
        "installations": [{
            "id": 1,
            "app_id": airlock_core::auth::AIRLOCK_SAFE_APP_ID,
            "app_slug": airlock_core::auth::AIRLOCK_SAFE_APP_SLUG,
            "account": { "login": "wyrd-company", "type": "Organization" },
            "repository_selection": "all",
            "permissions": {
                "administration": "read",
                "contents": "read",
                "metadata": "read"
            }
        }]
    })
}

/// Whether `text` carries anything shaped like a GitHub token.
fn carries_token(text: &str) -> bool {
    ["ghp_", "gho_", "ghs_", "ghr_", "github_pat_", "ghu_"]
        .iter()
        .any(|prefix| {
            text.match_indices(prefix).any(|(at, _)| {
                text[at + prefix.len()..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .count()
                    >= 20
            })
        })
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let [owner, repo, policy, out] = arguments.as_slice() else {
        panic!("usage: record_audit <owner> <repo> <policy> <out.json>");
    };
    let token = Zeroizing::new(
        std::env::var("AIRLOCK_RECORD_TOKEN").expect("AIRLOCK_RECORD_TOKEN holds the token"),
    );
    let recorder = Arc::new(Recorder {
        inner: ReqwestTransport::new(Limits::default().connect_timeout).expect("transport"),
        token,
        exchanges: Mutex::new(Vec::new()),
    });
    let request = AuditRequest::parse(
        &json!({
            "token": PLACEHOLDER,
            "owner": owner,
            "repo": repo,
            "policy": policy,
        })
        .to_string(),
    )
    .expect("request");
    let report = engine::audit(Arc::clone(&recorder) as Arc<dyn Transport>, &request)
        .await
        .expect("the audit completes");

    let exchanges = std::mem::take(&mut *recorder.exchanges.lock().expect("one thread"));
    let recording = json!({
        "comment": "GitHub's responses to one audit, recorded by crates/wasm/examples/record_audit.rs. No request header is kept. See docs/wasm.md.",
        "token": PLACEHOLDER,
        "request": { "owner": owner, "repo": repo, "policy": policy },
        "exchanges": exchanges,
    });
    let text = serde_json::to_string_pretty(&recording).expect("render") + "\n";
    assert!(
        !text.contains(recorder.token.as_str()) && !carries_token(&text) && !carries_token(&report),
        "the recording carries a token, so it was not written"
    );
    std::fs::write(out, text).expect("write the recording");
    eprintln!(
        "recorded {} exchanges to {out}",
        recording["exchanges"].as_array().map_or(0, Vec::len)
    );
}
