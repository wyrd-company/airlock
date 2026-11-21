//! The native half of the parity test: the module's own audit entry point,
//! compiled natively and run through reqwest.
//!
//! Reads an audit request as JSON on standard input, the same JSON the
//! module's `audit` takes, and prints the findings document. Used by
//! `crates/wasm/tests/parity.test.mjs`; see docs/wasm.md.

use std::io::Read as _;
use std::sync::Arc;

use airlock_core::limits::Limits;
use airlock_core::transport::ReqwestTransport;
use airlock_wasm::engine::{self, AuditRequest};

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        eprintln!("cannot read the request from standard input");
        return std::process::ExitCode::from(2);
    }
    let request = match AuditRequest::parse(&input) {
        Ok(request) => request,
        Err(error) => {
            eprintln!("{error}");
            return std::process::ExitCode::from(2);
        }
    };
    let transport = match ReqwestTransport::new(Limits::default().connect_timeout) {
        Ok(transport) => transport,
        Err(error) => {
            eprintln!("{error}");
            return std::process::ExitCode::from(2);
        }
    };
    match engine::audit(Arc::new(transport), &request).await {
        Ok(report) => {
            println!("{report}");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{}: {error}", error.kind);
            std::process::ExitCode::from(1)
        }
    }
}
