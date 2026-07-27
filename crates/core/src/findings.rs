//! The audit result document.
//!
//! One audit run produces one findings document: the audited repository, the
//! resolved policy identity and version, one finding per evaluated check, and a
//! summary. Every finding carries its statement and severity inline, so a
//! reader never has to look up what a bare rule identifier meant.
//!
//! The same document backs both output formats. The JSON form is the contract;
//! the text form is a rendering of it.
