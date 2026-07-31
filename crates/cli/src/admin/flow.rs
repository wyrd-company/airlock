//! Driving the device flow beside a terminal that has to stay responsive.
//!
//! The flow is asynchronous and the interface is a synchronous draw-and-read
//! loop, so the flow runs on its own thread with its own runtime and speaks to
//! the interface over channels. Three things follow from that shape, and all
//! three are deliberate.
//!
//! The device code airlock polls with never crosses the channel. It stays on
//! the worker, which is the only thing that needs it, so no interface state can
//! hold it and no rendering can print it. What crosses is [`Issued`], which is
//! the operator-facing half and nothing else.
//!
//! Everything server-supplied is sanitized here, on the way out, so there is
//! one boundary rather than one per screen.
//!
//! The grant crosses in its own variant, which the run loop takes before the
//! drawing state is told anything. [`Progress`] — the only thing the interface
//! is given — has no arm that could carry one.
//!
//! Shutdown is deterministic. Dropping [`Authorizing`] closes the request
//! channel, which every await on the worker is selecting against, so the worker
//! abandons whatever it is doing at once and is joined rather than detached.
//! Anything still queued is drained, and a `TokenGrant` zeroizes when it drops,
//! so no grant outlives the session in readable form on any of those paths.

use std::sync::mpsc::{Receiver as SyncReceiver, RecvTimeoutError, Sender as SyncSender};
use std::time::Duration;

use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::device::{
    DeviceCode, DeviceFlow, DeviceFlowConfig, PollOutcome, TokenGrant, GITHUB_LOGIN_BASE,
};

use super::identity;
use super::text::{self, ADDRESS_LIMIT, CAUSE_LIMIT, CODE_LIMIT};

/// Overrides GitHub's OAuth host, and only for a server on this machine.
///
/// The suite needs somewhere other than github.com to point the flow at. A
/// general override would be a way to redirect where an operator's approval
/// goes, which is exactly what binding the app identity at compile time exists
/// to prevent, so it is honoured only for the loopback: a redirect an attacker
/// can use has to reach a host they control, and this one cannot leave the
/// machine.
const LOGIN_URL_OVERRIDE: &str = "AIRLOCK_GITHUB_LOGIN_URL";

/// Overrides the GitHub API root, on exactly the same terms.
///
/// The catalogue read is made with the write credential, so an override that
/// could name any host would be a way to send that credential to one. It lives
/// beside the login override rather than beside its caller so that the write
/// path reads the environment in one file, which is a property the suite
/// asserts rather than a habit it hopes for.
const API_URL_OVERRIDE: &str = "AIRLOCK_API_URL";

/// How long the worker is given to notice that the session has gone.
///
/// Every await on it is selecting against the request channel, so it returns as
/// soon as that channel closes; this is the bound on a join that should be
/// immediate, so a wedged worker cannot hold the terminal instead.
const SHUTDOWN_BUDGET: Duration = Duration::from_secs(2);

/// The origin airlock sent its own device-flow request to.
///
/// This is what an address in the response has to match before a scan code will
/// encode it. It is derived from the base airlock actually used rather than
/// stated separately, so the two cannot drift: whatever host the request went
/// to is the only host a scanner can be pointed at.
///
/// An origin that cannot be read serialises to `null`, which matches no address
/// — the check fails closed, because a scan code is followed without being read.
#[must_use]
pub fn login_origin() -> String {
    url::Url::parse(&login_base())
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_default()
}

/// Where the console's own API reads go.
#[must_use]
pub fn api_base() -> String {
    match std::env::var(API_URL_OVERRIDE) {
        Ok(value) if is_loopback(&value) => value,
        _ => airlock_core::github::RestClientConfig::default().base_url,
    }
}

/// Where the device flow talks to.
#[must_use]
pub fn login_base() -> String {
    match std::env::var(LOGIN_URL_OVERRIDE) {
        Ok(value) if is_loopback(&value) => value,
        _ => GITHUB_LOGIN_BASE.to_owned(),
    }
}

/// Whether a base URL names a host on this machine.
///
/// Parsed with `url`, which is the crate reqwest resolves with, rather than
/// taken apart by hand, so there is no gap between what is validated and what is
/// dialled. A hand-rolled reading of the authority is what let
/// `http://localhost:80@attacker.example` through: the loopback name was
/// userinfo, and the host was somebody else's.
///
/// Three things are required, and each refuses a different attack: no userinfo,
/// because that is where a loopback name can be hidden; a host that *is* a
/// loopback address or is exactly `localhost`, because `localhost.attacker
/// .example` merely begins with one; and nothing in the path or the query,
/// because this value is concatenated with a path and a base carrying its own
/// would not mean what it reads as.
pub(super) fn is_loopback(base: &str) -> bool {
    let Ok(url) = url::Url::parse(base) else {
        return false;
    };
    if !matches!(url.scheme(), "http" | "https") {
        return false;
    }
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    if url.query().is_some() || url.fragment().is_some() {
        return false;
    }
    if !matches!(url.path(), "" | "/") {
        return false;
    }
    match url.host() {
        // `url` lower-cases and normalises the host before this sees it, so
        // `LocalHost` and `127.000.000.001` are already resolved.
        Some(url::Host::Domain(host)) => host == "localhost",
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

/// A device code, as the operator sees it.
///
/// The code airlock polls with is deliberately absent: it is credential-shaped,
/// it is not the operator's to type, and a type that has no field for it cannot
/// carry it to a screen. Both strings arrive sanitized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issued {
    /// The characters the operator types.
    pub user_code: String,
    /// Where they type them.
    pub verification_uri: String,
    /// How long the code is good for.
    pub expires_in: Duration,
    /// The wait GitHub asks for between polls.
    pub interval: Duration,
}

impl Issued {
    /// Take the operator-facing half of a device code response, made safe to
    /// draw.
    fn from_response(code: &DeviceCode) -> Self {
        Self {
            user_code: text::sanitize(&code.user_code, CODE_LIMIT),
            verification_uri: text::sanitize(&code.verification_uri, ADDRESS_LIMIT),
            expires_in: Duration::from_secs(code.expires_in),
            interval: Duration::from_secs(code.interval),
        }
    }
}

/// What the interface is told.
///
/// No arm carries a credential, and none can be added that does without this
/// type changing: the grant travels in [`Report`], which the run loop takes
/// apart before the drawing state is told anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    /// A device code arrived.
    CodeIssued(Box<Issued>),
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
}

/// What the worker sends.
pub enum Report {
    /// Something the interface should draw.
    Progress(Progress),
    /// The operator approved. The only variant that carries a credential, and
    /// it never reaches the interface: the run loop takes it here.
    Granted(Box<TokenGrant>),
}

impl std::fmt::Debug for Report {
    /// Redacting rather than absent: the enum is matched on in the run loop, so
    /// an error there wants a name, and no arm may print a value.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Progress(progress) => formatter.debug_tuple("Progress").field(progress).finish(),
            Self::Granted(_) => formatter.write_str("Granted"),
        }
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
    reports: SyncReceiver<Report>,
    /// Held in an `Option` so shutdown can drop it before joining. Closing this
    /// channel is the signal, and every await on the worker selects against it.
    requests: Option<Sender<Request>>,
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
        let (requests, request_receiver) = tokio::sync::mpsc::channel(1);
        let config = DeviceFlowConfig {
            base_url: login_base.to_owned(),
            ..DeviceFlowConfig::default()
        };
        let flow = DeviceFlow::new(identity::bound().client_id, config)?;
        let worker = std::thread::Builder::new()
            .name("airlock-device-flow".to_owned())
            .spawn(move || run(&flow, &report_sender, request_receiver))?;
        Ok(Self {
            reports,
            requests: Some(requests),
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
        if let Some(requests) = self.requests.as_ref() {
            match requests.try_send(Request::Reissue) {
                Ok(()) | Err(TrySendError::Full(_)) | Err(TrySendError::Closed(_)) => {}
            }
        }
    }

    /// Stop the worker and account for anything it had in hand.
    ///
    /// Ordered, and the order is the point. The request channel closes first,
    /// which every await on the worker is selecting against, so it abandons an
    /// in-flight poll rather than running it out. Then the queue is drained,
    /// dropping — and so zeroizing — a grant that arrived and was never read.
    /// Then the worker is joined, so a grant it acquires on the way out is
    /// dropped before this returns rather than on a thread nobody is waiting
    /// for. Then the queue is drained again, because the join is what lets the
    /// worker put one there.
    fn shut_down(&mut self) {
        drop(self.requests.take());
        self.drain();
        if let Some(worker) = self.worker.take() {
            let deadline = std::time::Instant::now() + SHUTDOWN_BUDGET;
            while !worker.is_finished() && std::time::Instant::now() < deadline {
                // Draining as it goes, so a grant sent during shutdown is
                // cleared even if the join below is abandoned.
                self.drain();
                std::thread::sleep(Duration::from_millis(10));
            }
            if worker.is_finished() {
                let _ = worker.join();
            }
        }
        self.drain();
    }

    /// Take everything queued and drop it.
    ///
    /// Dropping is what clears it: `TokenGrant` zeroizes on drop, so a grant
    /// that was never read is not left readable in a freed allocation.
    fn drain(&mut self) {
        while self.reports.try_recv().is_ok() {}
    }
}

impl Drop for Authorizing {
    fn drop(&mut self) {
        self.shut_down();
    }
}

/// The worker: acquire a code, poll it, and start again when it lapses.
fn run(flow: &DeviceFlow, reports: &SyncSender<Report>, requests: Receiver<Request>) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = reports.send(Report::Progress(Progress::Interrupted(text::sanitize(
                &format!("the device flow could not start: {error}"),
                CAUSE_LIMIT,
            ))));
            return;
        }
    };
    let mut requests = requests;
    runtime.block_on(async {
        let mut backoff = Duration::from_secs(2);
        loop {
            // Every await below is inside `interruptible`, so closing the
            // request channel abandons it rather than running it out. That is
            // what makes shutdown prompt, and what keeps a grant from being
            // acquired on a thread nobody is joining.
            let codes = match interruptible(&mut requests, flow.request_codes()).await {
                Interrupted::Finished(Ok(codes)) => {
                    backoff = Duration::from_secs(2);
                    codes
                }
                Interrupted::Finished(Err(error)) => {
                    if report(reports, Progress::Interrupted(cause(&error))).is_err() {
                        return;
                    }
                    match wait(&mut requests, backoff).await {
                        Waited::Gone => return,
                        Waited::Reissue | Waited::Elapsed => {}
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                    continue;
                }
                Interrupted::Reissue => continue,
                Interrupted::Gone => return,
            };
            if report(
                reports,
                Progress::CodeIssued(Box::new(Issued::from_response(&codes))),
            )
            .is_err()
            {
                return;
            }
            match poll(flow, reports, &mut requests, &codes).await {
                Poll::Granted | Poll::Gone => return,
                Poll::Restart => {}
            }
        }
    });
}

fn report(reports: &SyncSender<Report>, progress: Progress) -> Result<(), ()> {
    reports.send(Report::Progress(progress)).map_err(|_| ())
}

/// A transport or protocol failure, made safe to draw.
fn cause(error: &anyhow::Error) -> String {
    text::sanitize(&format!("{error:#}"), CAUSE_LIMIT)
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
    reports: &SyncSender<Report>,
    requests: &mut Receiver<Request>,
    codes: &DeviceCode,
) -> Poll {
    let mut interval = Duration::from_secs(codes.interval).max(Duration::from_secs(1));
    let deadline = std::time::Instant::now() + Duration::from_secs(codes.expires_in);
    loop {
        match wait(requests, interval).await {
            Waited::Reissue => return Poll::Restart,
            Waited::Elapsed => {}
            Waited::Gone => return Poll::Gone,
        }
        // Past the deadline the code is asked about once more rather than
        // declared lapsed unasked. An operator approving in a browser and
        // airlock's own clock reaching the deadline is a race airlock loses
        // only if it stops asking before GitHub answers, and the approval it
        // would throw away is a real one the operator would then have to give
        // again.
        let lapsed = std::time::Instant::now() >= deadline;
        let outcome = match interruptible(requests, flow.poll_once(&codes.device_code)).await {
            Interrupted::Finished(outcome) => outcome,
            Interrupted::Reissue => return Poll::Restart,
            Interrupted::Gone => return Poll::Gone,
        };
        let progress = match outcome {
            Ok(PollOutcome::Granted(grant)) => {
                // Sent, or dropped here — and dropping it zeroizes it, so the
                // interface having gone is not a grant left in memory.
                return match reports.send(Report::Granted(grant)) {
                    Ok(()) => Poll::Granted,
                    Err(_) => Poll::Gone,
                };
            }
            // The last question has been asked and answered with something
            // other than a grant, so the code has lapsed whatever else the
            // poll called it.
            _ if lapsed => Progress::Expired,
            Ok(PollOutcome::Pending) => Progress::Pending(interval),
            Ok(PollOutcome::SlowDown(seconds)) => {
                interval = interval
                    .saturating_add(Duration::from_secs(5))
                    .max(Duration::from_secs(seconds));
                Progress::SlowDown(interval)
            }
            Ok(PollOutcome::Expired) => Progress::Expired,
            Ok(PollOutcome::Denied) => Progress::Denied,
            Ok(PollOutcome::Failed(message)) => {
                Progress::Interrupted(text::sanitize(&message, CAUSE_LIMIT))
            }
            Err(error) => Progress::Interrupted(cause(&error)),
        };
        let restart = matches!(progress, Progress::Expired | Progress::Denied);
        if report(reports, progress).is_err() {
            return Poll::Gone;
        }
        if restart {
            return Poll::Restart;
        }
    }
}

/// What a wait ended with.
enum Waited {
    /// The operator pressed `r`.
    Reissue,
    /// The wait ran out.
    Elapsed,
    /// The interface has gone.
    Gone,
}

/// Wait, unless the interface asks for something or goes away first.
async fn wait(requests: &mut Receiver<Request>, duration: Duration) -> Waited {
    tokio::select! {
        received = requests.recv() => match received {
            Some(Request::Reissue) => Waited::Reissue,
            None => Waited::Gone,
        },
        () = tokio::time::sleep(duration) => Waited::Elapsed,
    }
}

/// How an awaited call ended.
enum Interrupted<T> {
    /// It finished.
    Finished(T),
    /// The operator asked for a new code while it was in flight.
    Reissue,
    /// The interface went away while it was in flight.
    Gone,
}

/// Run a request, abandoning it if the interface asks for something or goes.
///
/// Abandoning a poll means dropping the future mid-flight, which is what makes
/// shutdown immediate rather than bounded by a request timeout — and, on the
/// closing path, what keeps a grant from arriving after the last thing that
/// could account for it has gone.
async fn interruptible<T>(
    requests: &mut Receiver<Request>,
    work: impl std::future::Future<Output = T>,
) -> Interrupted<T> {
    tokio::select! {
        // The request channel is checked first so that a shutdown racing a
        // completing request resolves as a shutdown.
        biased;
        received = requests.recv() => match received {
            Some(Request::Reissue) => Interrupted::Reissue,
            None => Interrupted::Gone,
        },
        finished = work => Interrupted::Finished(finished),
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

    async fn server_with(codes: serde_json::Value, token: serde_json::Value) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/login/device/code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(codes))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token))
            .mount(&server)
            .await;
        server
    }

    async fn server(token: serde_json::Value) -> MockServer {
        server_with(code_response(), token).await
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

    fn is_progress(report: &Report, wanted: impl Fn(&Progress) -> bool) -> bool {
        matches!(report, Report::Progress(progress) if wanted(progress))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_approved_flow_reports_a_grant_and_nothing_else_carries_one() {
        let server = server(serde_json::json!({ "access_token": "ghu_approved" })).await;
        let authorizing = Authorizing::start(&server.uri()).expect("the flow starts");

        let issued = until(&authorizing, |report| {
            is_progress(report, |progress| {
                matches!(progress, Progress::CodeIssued(_))
            })
        })
        .expect("a code was issued");
        let Report::Progress(Progress::CodeIssued(issued)) = issued else {
            unreachable!()
        };
        assert_eq!(issued.user_code, "WDJB-MJHT");
        assert_eq!(issued.expires_in, Duration::from_secs(900));

        let granted =
            until(&authorizing, |report| matches!(report, Report::Granted(_))).expect("a grant");
        let Report::Granted(grant) = granted else {
            unreachable!()
        };
        assert_eq!(grant.access_token, "ghu_approved");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_code_airlock_polls_with_does_not_cross_the_channel() {
        let server = server(serde_json::json!({ "error": "authorization_pending" })).await;
        let authorizing = Authorizing::start(&server.uri()).expect("the flow starts");
        let issued = until(&authorizing, |report| {
            is_progress(report, |progress| {
                matches!(progress, Progress::CodeIssued(_))
            })
        })
        .expect("a code was issued");
        // `Issued` has no field for it, so the reading available is the whole
        // of what the interface can ever be given.
        let printed = format!("{issued:?}");
        assert!(!printed.contains("never-crosses-the-channel"), "{printed}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_hostile_code_response_cannot_reach_the_interface_unsanitized() {
        // A server that answers with terminal instructions rather than a code.
        let hostile = serde_json::json!({
            "device_code": "polled-with",
            "user_code": "WDJB\u{1b}[2J-MJHT",
            "verification_uri": "https://github.com\u{202e}/moc.rekcatta//:sptth",
            "expires_in": 900,
            "interval": 0,
        });
        let server = server_with(hostile, serde_json::json!({ "error": "slow_down" })).await;
        let authorizing = Authorizing::start(&server.uri()).expect("the flow starts");

        let issued = until(&authorizing, |report| {
            is_progress(report, |progress| {
                matches!(progress, Progress::CodeIssued(_))
            })
        })
        .expect("a code was issued");
        let Report::Progress(Progress::CodeIssued(issued)) = issued else {
            unreachable!()
        };
        assert!(
            !issued.user_code.chars().any(char::is_control),
            "{:?}",
            issued.user_code
        );
        assert!(
            !issued.verification_uri.contains('\u{202e}'),
            "{:?}",
            issued.verification_uri
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_hostile_error_description_cannot_reach_the_interface_unsanitized() {
        let server = server_with(
            serde_json::json!({
                "error": "something_new",
                "error_description": "\u{1b}[2Jno credential stored\u{1b}[1;1H",
            }),
            serde_json::json!({}),
        )
        .await;
        let authorizing = Authorizing::start(&server.uri()).expect("the flow starts");
        let reported = until(&authorizing, |report| {
            is_progress(report, |progress| {
                matches!(progress, Progress::Interrupted(_))
            })
        })
        .expect("the failure is reported");
        let Report::Progress(Progress::Interrupted(cause)) = reported else {
            unreachable!()
        };
        assert!(!cause.chars().any(char::is_control), "{cause:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_denial_is_reported_and_a_new_code_follows_it_in_place() {
        let server = server(serde_json::json!({ "error": "access_denied" })).await;
        let authorizing = Authorizing::start(&server.uri()).expect("the flow starts");

        assert!(
            until(&authorizing, |report| is_progress(report, |progress| {
                matches!(progress, Progress::Denied)
            }))
            .is_some(),
            "the denial is reported"
        );
        assert!(
            until(&authorizing, |report| is_progress(report, |progress| {
                matches!(progress, Progress::CodeIssued(_))
            }))
            .is_some(),
            "a replacement code is issued without the session restarting"
        );
    }

    /// A code that lapses the moment it is issued.
    fn lapsing_code_response() -> serde_json::Value {
        serde_json::json!({
            "device_code": "never-crosses-the-channel",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://github.com/login/device",
            "expires_in": 0,
            "interval": 0,
        })
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_approval_that_lands_as_the_validity_runs_out_is_taken() {
        // The ceremony race: the operator approves in the browser at the same
        // moment airlock's clock reaches the deadline. The approval is real,
        // and a flow that declared expiry without asking would throw it away
        // and make the operator approve a second code for no reason.
        let server = server_with(
            lapsing_code_response(),
            serde_json::json!({ "access_token": "ghu_approved_at_the_last_moment" }),
        )
        .await;
        let authorizing = Authorizing::start(&server.uri()).expect("the flow starts");

        let granted = until(&authorizing, |report| matches!(report, Report::Granted(_)))
            .expect("the late approval is taken rather than discarded");
        let Report::Granted(grant) = granted else {
            unreachable!()
        };
        assert_eq!(grant.access_token, "ghu_approved_at_the_last_moment");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_code_that_lapses_unapproved_is_still_reported_as_expired() {
        // The other half: asking once more is not the same as never expiring.
        let server = server_with(
            lapsing_code_response(),
            serde_json::json!({ "error": "authorization_pending" }),
        )
        .await;
        let authorizing = Authorizing::start(&server.uri()).expect("the flow starts");
        assert!(
            until(&authorizing, |report| is_progress(report, |progress| {
                matches!(progress, Progress::Expired)
            }))
            .is_some(),
            "the lapse is reported"
        );
        assert!(
            until(&authorizing, |report| is_progress(report, |progress| {
                matches!(progress, Progress::CodeIssued(_))
            }))
            .is_some(),
            "a replacement code follows it in place"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unreachable_host_is_an_interruption_rather_than_an_exit() {
        // Port 1 on the loopback refuses immediately, which is the transport
        // failing rather than GitHub answering.
        let authorizing = Authorizing::start("http://127.0.0.1:1").expect("the flow starts");
        assert!(
            until(&authorizing, |report| is_progress(report, |progress| {
                matches!(progress, Progress::Interrupted(_))
            }))
            .is_some(),
            "the transport failure is reported"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_loopback_host_cannot_redirect_the_flow_off_the_machine() {
        // The console's half of the redirect property. The base URL is a
        // validated loopback and stays one, so `is_loopback` is satisfied and
        // says nothing useful: what would have left the machine is the second
        // hop, which it never sees. Nothing that arrives from the far side may
        // reach the screen, so the redirect has to be a reported interruption
        // rather than an issued code.
        let attacker = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "device_code": "chosen-by-the-redirect",
                "user_code": "AAAA-AAAA",
                "verification_uri": "https://attacker.example/login/device",
                "expires_in": 900,
                "interval": 0,
            })))
            .mount(&attacker)
            .await;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/login/device/code"))
            .respond_with(ResponseTemplate::new(307).insert_header(
                "location",
                &*format!("{}/login/device/code", attacker.uri()),
            ))
            .mount(&server)
            .await;

        let authorizing = Authorizing::start(&server.uri()).expect("the flow starts");
        assert!(
            until(&authorizing, |report| is_progress(report, |progress| {
                matches!(progress, Progress::Interrupted(_))
            }))
            .is_some(),
            "the redirect is reported as an interruption"
        );
        assert!(
            attacker
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "the flow followed a redirect off the host it validated"
        );
        // Nothing the far side wrote can be on screen, because nothing was ever
        // asked for it.
        assert!(
            until(&authorizing, |report| is_progress(report, |progress| {
                matches!(progress, Progress::CodeIssued(_))
            }))
            .is_none(),
            "a code from the redirected host reached the interface"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn shutdown_stops_the_worker_rather_than_detaching_it() {
        // A server that accepts the poll and then says nothing for far longer
        // than any shutdown should wait. If the worker ran the request out, the
        // drop below would take the server's delay rather than the budget.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/login/device/code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(code_response()))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "access_token": "ghu_late" }))
                    .set_delay(Duration::from_secs(20)),
            )
            .mount(&server)
            .await;

        let authorizing = Authorizing::start(&server.uri()).expect("the flow starts");
        until(&authorizing, |report| {
            is_progress(report, |progress| {
                matches!(progress, Progress::CodeIssued(_))
            })
        })
        .expect("a code was issued");

        let started = std::time::Instant::now();
        drop(authorizing);
        let took = started.elapsed();
        assert!(
            took < SHUTDOWN_BUDGET + Duration::from_secs(1),
            "shutdown waited {took:?} on an in-flight poll"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_grant_queued_and_never_read_is_dropped_by_shutdown() {
        let server = server(serde_json::json!({ "access_token": "ghu_never_read" })).await;
        let mut authorizing = Authorizing::start(&server.uri()).expect("the flow starts");
        // Long enough for the grant to be sent and to sit unread in the queue.
        std::thread::sleep(Duration::from_millis(400));

        authorizing.shut_down();

        assert!(
            authorizing.next_report(Duration::from_millis(50)).is_none(),
            "shutdown left a report — and so possibly a grant — in the queue"
        );
        assert!(
            authorizing.worker.is_none(),
            "shutdown left the worker unaccounted for"
        );
    }

    #[test]
    fn shutting_down_twice_is_harmless() {
        let mut authorizing = Authorizing::start("http://127.0.0.1:1").expect("the flow starts");
        authorizing.shut_down();
        authorizing.shut_down();
    }

    #[test]
    fn the_login_host_override_is_honoured_only_for_this_machine() {
        for allowed in [
            "http://127.0.0.1:8080",
            "http://localhost",
            "https://localhost:443/",
            "http://[::1]:9000",
            "http://LocalHost:1234",
            "http://127.0.0.2:9",
        ] {
            assert!(is_loopback(allowed), "{allowed}");
        }
        for refused in [
            // The finding: userinfo that makes a loopback name the username.
            "http://localhost:80@attacker.example",
            "http://127.0.0.1@attacker.example/",
            "http://user:pass@localhost",
            // A loopback name as a label of somebody else's domain.
            "http://localhost.attacker.example",
            "http://127.0.0.1.attacker.example",
            "http://attacker.example/localhost",
            "http://attacker.example/?x=localhost",
            // A base that carries its own path or query, which is concatenated
            // with one and would not mean what it reads as.
            "http://127.0.0.1:8080/login",
            "http://localhost/?redirect=https://attacker.example",
            // Not a loopback at all.
            "https://github.com",
            // Malformed, and refused rather than guessed at.
            "http://[::1",
            "http://[::1]x",
            "http://localhost:notaport",
            "http://localhost:8080\u{1b}[2J",
            "http://local host",
            "127.0.0.1:8080",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "",
        ] {
            assert!(!is_loopback(refused), "{refused}");
        }
    }

    #[test]
    fn the_api_root_override_is_honoured_only_for_this_machine() {
        // No override is set in this process, so the base is GitHub's — and the
        // decision the override is made of is the loopback test above.
        assert_eq!(api_base(), "https://api.github.com");
        assert!(is_loopback("http://127.0.0.1:8080"));
        assert!(!is_loopback("https://api.github.com.attacker.example"));
    }

    #[test]
    fn the_origin_a_scan_code_is_held_to_is_the_one_the_request_went_to() {
        // No override is set in this process, so the origin is GitHub's — and
        // it is read from the base rather than written down twice.
        assert_eq!(login_origin(), "https://github.com");
        assert_eq!(login_base(), GITHUB_LOGIN_BASE);
    }

    #[test]
    fn the_override_falls_back_rather_than_failing_when_it_is_refused() {
        // The environment is process-wide, so this asserts the decision rather
        // than setting the variable: `login_base` is the two branches below.
        assert!(is_loopback("http://127.0.0.1:9"));
        assert!(!is_loopback("http://localhost:80@attacker.example"));
        assert_eq!(GITHUB_LOGIN_BASE, "https://github.com");
    }

    #[test]
    fn a_report_never_prints_anything_it_carries() {
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
