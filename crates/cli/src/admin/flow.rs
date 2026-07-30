//! Driving the device flow beside a terminal that has to stay responsive.
//!
//! The flow is asynchronous and the interface is a synchronous draw-and-read
//! loop, so the flow runs on its own thread with its own runtime and speaks to
//! the interface over channels. Two things follow from that shape, and both are
//! deliberate.
//!
//! The device code airlock polls with never crosses the channel. It stays on
//! the worker, which is the only thing that needs it, so no interface state can
//! hold it and no rendering can print it.
//!
//! The grant crosses exactly once, into the run loop, and is turned into a
//! [`SessionCredential`] there. It is never handed to the drawing state: what
//! renders the screen cannot reach the credential, which is stronger than
//! remembering not to draw it.

use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, SyncSender, TrySendError};
use std::time::Duration;

use crate::device::{
    DeviceCode, DeviceFlow, DeviceFlowConfig, PollOutcome, TokenGrant, GITHUB_LOGIN_BASE,
};

use super::identity;

/// Overrides GitHub's OAuth host, and only for a server on this machine.
///
/// The suite needs somewhere other than github.com to point the flow at. A
/// general override would be a way to redirect where an operator's approval
/// goes, which is exactly what binding the app identity at compile time exists
/// to prevent, so it is honoured only for the loopback: a redirect an attacker
/// can use has to reach a host they control, and this one cannot leave the
/// machine.
const LOGIN_URL_OVERRIDE: &str = "AIRLOCK_GITHUB_LOGIN_URL";

/// The hosts the override may name.
const LOOPBACK: &[&str] = &["127.0.0.1", "localhost", "[::1]"];

/// Where the device flow talks to.
#[must_use]
pub fn login_base() -> String {
    match std::env::var(LOGIN_URL_OVERRIDE) {
        Ok(value) if is_loopback(&value) => value,
        _ => GITHUB_LOGIN_BASE.to_owned(),
    }
}

/// Whether a base URL names a host on this machine.
fn is_loopback(base: &str) -> bool {
    let Some(rest) = base
        .strip_prefix("http://")
        .or_else(|| base.strip_prefix("https://"))
    else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or_default();
    let host = match authority.rsplit_once(':') {
        // An IPv6 literal keeps its brackets, so a colon inside them is not a
        // port separator.
        Some((head, _)) if !head.is_empty() && !authority.ends_with(']') => head,
        _ => authority,
    };
    LOOPBACK.contains(&host)
}

/// What the worker tells the interface.
pub enum Report {
    /// A device code arrived.
    CodeIssued(Box<DeviceCode>),
    /// One poll came back with the authorization still pending, and the wait
    /// before the next one. The interval is carried because a poll that
    /// succeeds after a transport failure is what tells the screen the
    /// interruption is over, and the screen has to say how often it is polling
    /// again.
    Pending(Duration),
    /// GitHub asked airlock to poll less often.
    SlowDown(Duration),
    /// The code lapsed.
    Expired,
    /// The authorization was declined.
    Denied,
    /// The transport failed, or GitHub reported something unhandled.
    Interrupted(String),
    /// The operator approved. This is the only message carrying a credential,
    /// and it is sent once.
    Granted(Box<TokenGrant>),
}

impl std::fmt::Debug for Report {
    /// Redacting rather than absent: the enum is matched on in the run loop, so
    /// an error there wants a name, and no arm may print a value.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::CodeIssued(_) => "CodeIssued",
            Self::Pending(_) => "Pending",
            Self::SlowDown(_) => "SlowDown",
            Self::Expired => "Expired",
            Self::Denied => "Denied",
            Self::Interrupted(_) => "Interrupted",
            Self::Granted(_) => "Granted",
        };
        formatter.write_str(name)
    }
}

/// What the interface asks of the worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// Abandon the current code and ask for a new one.
    Reissue,
}

/// The interface's end of the worker.
pub struct Authorizing {
    reports: Receiver<Report>,
    requests: SyncSender<Request>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Authorizing {
    /// Start the device flow for the identity this build is bound to.
    ///
    /// # Errors
    ///
    /// Returns an error when the runtime or the HTTP stack cannot be built.
    pub fn start(login_base: &str) -> anyhow::Result<Self> {
        let (report_sender, reports) = std::sync::mpsc::channel();
        // A bound of one: the interface only ever has one outstanding request,
        // and an unbounded queue of them would let a held key reissue forever.
        let (requests, request_receiver) = std::sync::mpsc::sync_channel(1);
        let config = DeviceFlowConfig {
            base_url: login_base.to_owned(),
            ..DeviceFlowConfig::default()
        };
        let flow = DeviceFlow::new(identity::bound().client_id, config)?;
        let worker = std::thread::Builder::new()
            .name("airlock-device-flow".to_owned())
            .spawn(move || run(&flow, &report_sender, &request_receiver))?;
        Ok(Self {
            reports,
            requests,
            worker: Some(worker),
        })
    }

    /// Wait up to `timeout` for the next report.
    ///
    /// `None` means nothing happened in that window, which is the interface's
    /// cue to tick its clocks and redraw.
    pub fn next_report(&self, timeout: Duration) -> Option<Report> {
        match self.reports.recv_timeout(timeout) {
            Ok(report) => Some(report),
            Err(RecvTimeoutError::Timeout) => None,
            // The worker is gone, which happens once it has sent the grant.
            Err(RecvTimeoutError::Disconnected) => None,
        }
    }

    /// Ask for a new code.
    ///
    /// A request that does not fit is dropped rather than queued: the worker is
    /// already reissuing, and a second request would only reissue again.
    pub fn reissue(&self) {
        match self.requests.try_send(Request::Reissue) {
            Ok(()) | Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {}
        }
    }
}

impl Drop for Authorizing {
    fn drop(&mut self) {
        // Dropping the request sender is what tells the worker to stop; it
        // observes the disconnection at its next wait. The handle is dropped
        // rather than joined, because a poll already in flight holds a request
        // timeout the operator should not have to sit through on the way out.
        if let Some(worker) = self.worker.take() {
            drop(worker);
        }
    }
}

/// The worker: acquire a code, poll it, and start again when it lapses.
fn run(flow: &DeviceFlow, reports: &Sender<Report>, requests: &Receiver<Request>) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = reports.send(Report::Interrupted(format!(
                "the device flow could not start: {error}"
            )));
            return;
        }
    };
    runtime.block_on(async {
        let mut backoff = Duration::from_secs(2);
        loop {
            let codes = match flow.request_codes().await {
                Ok(codes) => {
                    backoff = Duration::from_secs(2);
                    codes
                }
                Err(error) => {
                    if reports
                        .send(Report::Interrupted(format!("{error:#}")))
                        .is_err()
                    {
                        return;
                    }
                    if wait(requests, backoff).is_none() {
                        return;
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                    continue;
                }
            };
            if reports
                .send(Report::CodeIssued(Box::new(codes.clone())))
                .is_err()
            {
                return;
            }
            match poll(flow, reports, requests, &codes).await {
                Poll::Granted | Poll::Gone => return,
                Poll::Restart => {}
            }
        }
    });
}

/// How a code's polling ended.
enum Poll {
    /// The operator approved; the grant has been sent.
    Granted,
    /// The interface has gone away.
    Gone,
    /// Ask for a new code.
    Restart,
}

async fn poll(
    flow: &DeviceFlow,
    reports: &Sender<Report>,
    requests: &Receiver<Request>,
    codes: &DeviceCode,
) -> Poll {
    let mut interval = Duration::from_secs(codes.interval).max(Duration::from_secs(1));
    let deadline = std::time::Instant::now() + Duration::from_secs(codes.expires_in);
    loop {
        match wait(requests, interval) {
            // The operator pressed `r`.
            Some(true) => return Poll::Restart,
            Some(false) => {}
            None => return Poll::Gone,
        }
        if std::time::Instant::now() >= deadline {
            return match reports.send(Report::Expired) {
                Ok(()) => Poll::Restart,
                Err(_) => Poll::Gone,
            };
        }
        let report = match flow.poll_once(&codes.device_code).await {
            Ok(PollOutcome::Granted(grant)) => {
                return match reports.send(Report::Granted(grant)) {
                    Ok(()) | Err(_) => Poll::Granted,
                }
            }
            Ok(PollOutcome::Pending) => Report::Pending(interval),
            Ok(PollOutcome::SlowDown(seconds)) => {
                interval = interval
                    .saturating_add(Duration::from_secs(5))
                    .max(Duration::from_secs(seconds));
                Report::SlowDown(interval)
            }
            Ok(PollOutcome::Expired) => Report::Expired,
            Ok(PollOutcome::Denied) => Report::Denied,
            Ok(PollOutcome::Failed(message)) => Report::Interrupted(message),
            Err(error) => Report::Interrupted(format!("{error:#}")),
        };
        let restart = matches!(report, Report::Expired | Report::Denied);
        if reports.send(report).is_err() {
            return Poll::Gone;
        }
        if restart {
            return Poll::Restart;
        }
    }
}

/// Wait, unless the interface asks for something or goes away first.
///
/// `Some(true)` is a reissue, `Some(false)` is the wait elapsing, and `None` is
/// the interface having gone.
fn wait(requests: &Receiver<Request>, duration: Duration) -> Option<bool> {
    match requests.recv_timeout(duration) {
        Ok(Request::Reissue) => Some(true),
        Err(RecvTimeoutError::Timeout) => Some(false),
        Err(RecvTimeoutError::Disconnected) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn code_response() -> serde_json::Value {
        serde_json::json!({
            "device_code": "never-crosses-the-channel",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://github.com/login/device",
            "expires_in": 900,
            "interval": 0,
        })
    }

    async fn server(token: serde_json::Value) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/login/device/code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(code_response()))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token))
            .mount(&server)
            .await;
        server
    }

    /// Collect reports until one matches, or give up.
    fn until(
        authorizing: &Authorizing,
        mut matches: impl FnMut(&Report) -> bool,
    ) -> Option<Report> {
        for _ in 0..50 {
            if let Some(report) = authorizing.next_report(Duration::from_millis(200)) {
                if matches(&report) {
                    return Some(report);
                }
            }
        }
        None
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_approved_flow_reports_a_grant_and_nothing_else_carries_one() {
        let server = server(serde_json::json!({ "access_token": "ghu_approved" })).await;
        let authorizing = Authorizing::start(&server.uri()).expect("the flow starts");

        let issued = until(&authorizing, |report| {
            matches!(report, Report::CodeIssued(_))
        })
        .expect("a code was issued");
        let Report::CodeIssued(codes) = issued else {
            unreachable!()
        };
        assert_eq!(codes.user_code, "WDJB-MJHT");

        let granted =
            until(&authorizing, |report| matches!(report, Report::Granted(_))).expect("a grant");
        let Report::Granted(grant) = granted else {
            unreachable!()
        };
        assert_eq!(grant.access_token, "ghu_approved");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_denial_is_reported_and_a_new_code_follows_it_in_place() {
        let server = server(serde_json::json!({ "error": "access_denied" })).await;
        let authorizing = Authorizing::start(&server.uri()).expect("the flow starts");

        assert!(
            until(&authorizing, |report| matches!(report, Report::Denied)).is_some(),
            "the denial is reported"
        );
        assert!(
            until(&authorizing, |report| matches!(
                report,
                Report::CodeIssued(_)
            ))
            .is_some(),
            "a replacement code is issued without the session restarting"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unreachable_host_is_an_interruption_rather_than_an_exit() {
        // Port 1 on the loopback refuses immediately, which is the transport
        // failing rather than GitHub answering.
        let authorizing = Authorizing::start("http://127.0.0.1:1").expect("the flow starts");
        assert!(
            until(&authorizing, |report| matches!(
                report,
                Report::Interrupted(_)
            ))
            .is_some(),
            "the transport failure is reported"
        );
    }

    #[test]
    fn the_login_host_override_is_honoured_only_for_this_machine() {
        for allowed in [
            "http://127.0.0.1:8080",
            "http://localhost",
            "https://localhost:443/",
            "http://[::1]:9000",
        ] {
            assert!(is_loopback(allowed), "{allowed}");
        }
        for refused in [
            "https://github.com",
            "https://127.0.0.1.example.com",
            "http://evil.test/127.0.0.1",
            "127.0.0.1:8080",
            "",
        ] {
            assert!(!is_loopback(refused), "{refused}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_report_never_prints_anything_it_carries() {
        let grant = TokenGrant {
            access_token: "ghu_secret".to_owned(),
            expires_in: None,
            refresh_token: Some("ghr_secret".to_owned()),
            refresh_token_expires_in: None,
        };
        let printed = format!("{:?}", Report::Granted(Box::new(grant)));
        assert_eq!(printed, "Granted");
    }
}
