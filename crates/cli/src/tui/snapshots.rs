//! Snapshot proof of the rendering.
//!
//! Every case draws the whole interface into a buffer and records two grids:
//! the characters, and one legend key per cell naming the style that cell
//! carries. The second grid is what makes the palettes and `NO_COLOR`
//! reviewable — the character grid is identical across all three, which is
//! precisely the property being asserted.
//!
//! Run with `UPDATE_SNAPSHOTS=1` to rewrite the recorded files.

use std::fmt::Write as _;
#[cfg_attr(feature = "test-identity", allow(unused_imports))]
use std::path::PathBuf;

use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};
use ratatui::Terminal;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::admin::catalogue::{Catalogue, Installation, Listing, Repository};
use crate::admin::flow::Issued;
use crate::admin::sign_in::SignIn;
use airlock_core::github::{AccountKind, RepositorySelection};

use super::app::App;
use super::chrome::{FLOOR_HEIGHT, FLOOR_WIDTH, REFERENCE_HEIGHT, REFERENCE_WIDTH};
use super::screen::Screen;
use super::theme::{ColorMode, Theme};

/// The version printed in a snapshot, so a release never rewrites every file.
const VERSION: &str = "0.0.0";

/// The characters used as legend keys, in order of first appearance.
const KEYS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

struct Case {
    name: &'static str,
    screen: Screen,
    theme: Theme,
    color: ColorMode,
    width: u16,
    height: u16,
    /// The sign-in state to open on, where the case is one of the five.
    flow: Option<SignIn>,
    /// The catalogue to open on, where the case is a selection screen.
    selection: Option<Selection>,
    /// The run to open on, where the case is the findings screen.
    run: Option<Run>,
}

/// A run the findings screen draws, and where the operator has moved inside it.
///
/// Reached by pressing the keys rather than by setting the state, so a recorded
/// screen is one the interface can actually be driven to.
#[derive(Clone)]
struct Run {
    report: airlock_core::findings::Report,
    deliveries: super::findings::Deliveries,
    /// How many times `↓` has been pressed.
    moved: usize,
    /// The keys pressed after moving. A newline stands for `↵`, which is how a
    /// recorded case reaches a screen the queue opens.
    keys: &'static str,
}

impl Run {
    fn of(report: airlock_core::findings::Report) -> Self {
        Self {
            report,
            deliveries: super::findings::fixture::deliveries(),
            moved: 0,
            keys: "",
        }
    }

    const fn driven(mut self, moved: usize, keys: &'static str) -> Self {
        self.moved = moved;
        self.keys = keys;
        self
    }
}

/// A catalogue, and where the operator has moved to inside it.
///
/// Reached by pressing the keys rather than by setting the fields, so a
/// recorded screen is one the interface can actually be driven to.
#[derive(Clone)]
struct Selection {
    catalogue: Catalogue,
    /// How many times `↓` has been pressed.
    moved: usize,
    /// What has been typed into the repository filter, if anything.
    filter: &'static str,
}

fn installation(
    account: &str,
    kind: AccountKind,
    selection: RepositorySelection,
    names: &[&str],
) -> Installation {
    Installation {
        id: 7,
        account: account.to_owned(),
        kind,
        selection,
        listing: Listing::Read {
            repositories: names
                .iter()
                .map(|name| Repository {
                    owner: account.to_owned(),
                    name: (*name).to_owned(),
                    visibility: if name.starts_with("public") {
                        "public".to_owned()
                    } else {
                        "private".to_owned()
                    },
                    default_branch: Some("main".to_owned()),
                })
                .collect(),
            total: names.len() as u64,
            truncated: false,
        },
    }
}

/// An installation of four hundred repositories that airlock read part of.
///
/// The reading that matters is that neither screen calls what it holds the
/// whole of it: the row says both numbers and the table counts against the
/// installation rather than against itself.
fn prefix() -> Catalogue {
    let mut installation = installation(
        "acme-industries",
        AccountKind::Organization,
        RepositorySelection::All,
        &["widget", "sprocket", "public-flywheel"],
    );
    installation.listing = Listing::Read {
        repositories: installation.listing.repositories().to_vec(),
        total: 400,
        truncated: true,
    };
    Catalogue::of(vec![installation])
}

/// An organization reaching everything, and a scoped user account beside it.
fn catalogue() -> Catalogue {
    Catalogue::of(vec![
        installation(
            "acme-industries",
            AccountKind::Organization,
            RepositorySelection::All,
            &["widget", "sprocket", "public-flywheel"],
        ),
        installation(
            "sample-operator",
            AccountKind::UserAccount,
            RepositorySelection::Selected,
            &["notes"],
        ),
    ])
}

/// The device code every sign-in snapshot is drawn from.
///
/// A fixture, and the specification says as much: illustrative values are
/// shapes. What is asserted is that the interface prints what it was given.
fn fixture() -> Issued {
    Issued {
        user_code: "WDJB-MJHT".to_owned(),
        verification_uri: "https://github.com/login/device".to_owned(),
        expires_in: std::time::Duration::from_secs(900),
        interval: std::time::Duration::from_secs(5),
    }
}

/// Each of the five states, with the slug its snapshot is filed under.
fn flows() -> Vec<(&'static str, SignIn)> {
    let awaiting = || {
        let mut state = SignIn::opening();
        state.code_issued(&fixture());
        state
    };
    let mut interrupted = awaiting();
    interrupted.tick(std::time::Duration::from_secs(63));
    interrupted.interrupted("connection reset by peer");
    let mut awaited = awaiting();
    awaited.polled();
    awaited.polled();
    awaited.tick(std::time::Duration::from_secs(28));
    vec![
        ("requesting", SignIn::opening()),
        ("awaiting", awaited),
        ("expired", SignIn::Expired),
        ("denied", SignIn::Denied),
        ("interrupted", interrupted),
    ]
}

fn render(case: &Case) -> String {
    let backend = TestBackend::new(case.width, case.height);
    let mut terminal = Terminal::new(backend).expect("a test terminal");
    let mut app = match case.flow.clone() {
        Some(state) => App::new(VERSION, case.color)
            .at(case.screen, case.theme)
            .signing_in(state),
        None => App::new(VERSION, case.color).at(case.screen, case.theme),
    };
    if let Some(selection) = case.selection.clone() {
        app = app
            .with_catalogue(selection.catalogue)
            .at(case.screen, case.theme);
        let mut press = |code| {
            app.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
        };
        for _ in 0..selection.moved {
            press(KeyCode::Down);
        }
        if !selection.filter.is_empty() {
            press(KeyCode::Char('/'));
            for character in selection.filter.chars() {
                press(KeyCode::Char(character));
            }
        }
    }
    if let Some(run) = case.run.clone() {
        app.observed_run(&run.report, &run.deliveries);
        let mut press = |code| {
            app.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
        };
        for _ in 0..run.moved {
            press(KeyCode::Down);
        }
        for character in run.keys.chars() {
            press(if character == '\n' {
                KeyCode::Enter
            } else {
                KeyCode::Char(character)
            });
        }
    }
    let app = app;
    terminal
        .draw(|frame| app.render(frame.area(), frame.buffer_mut()))
        .expect("the interface draws");
    serialise(case, terminal.backend().buffer())
}

fn serialise(case: &Case, buffer: &Buffer) -> String {
    let mut legend: Vec<String> = Vec::new();
    let mut text = String::new();
    let mut styles = String::new();
    for y in 0..case.height {
        for x in 0..case.width {
            let cell = buffer.cell((x, y)).expect("the cell is in the buffer");
            let symbol = cell.symbol();
            text.push_str(if symbol.is_empty() { " " } else { symbol });
            let described = describe(cell.fg, cell.bg, cell.modifier);
            let index = match legend.iter().position(|entry| *entry == described) {
                Some(index) => index,
                None => {
                    legend.push(described);
                    legend.len() - 1
                }
            };
            styles.push(char::from(
                *KEYS
                    .get(index)
                    .expect("the frame uses fewer styles than keys"),
            ));
        }
        text.push('\n');
        styles.push('\n');
    }

    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} \u{b7} {}x{} \u{b7} theme {} \u{b7} {}",
        case.name,
        case.width,
        case.height,
        case.theme.name(),
        match case.color {
            ColorMode::Color => "colour",
            ColorMode::NoColor => "NO_COLOR",
        }
    );
    out.push_str("--- text ---\n");
    out.push_str(&text);
    out.push_str("--- style keys ---\n");
    out.push_str(&styles);
    out.push_str("--- legend ---\n");
    for (index, entry) in legend.iter().enumerate() {
        let _ = writeln!(out, "{} {entry}", char::from(KEYS[index]));
    }
    out
}

fn describe(fg: Color, bg: Color, modifier: Modifier) -> String {
    let mut out = format!("fg={} bg={}", name(fg), name(bg));
    if !modifier.is_empty() {
        let _ = write!(out, " {modifier:?}");
    }
    out
}

fn name(color: Color) -> String {
    match color {
        Color::Reset => "reset".to_string(),
        Color::Rgb(r, g, b) => format!("#{r:02X}{g:02X}{b:02X}"),
        other => format!("{other:?}"),
    }
}

#[cfg_attr(feature = "test-identity", allow(dead_code))]
fn path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots/tui")
        .join(format!("{name}.txt"))
}

#[cfg_attr(feature = "test-identity", allow(dead_code))]
fn check(case: &Case) {
    let rendered = render(case);
    let path = path(case.name);
    if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
        std::fs::create_dir_all(path.parent().expect("the snapshot has a directory"))
            .expect("the snapshot directory is writable");
        std::fs::write(&path, &rendered).expect("the snapshot is writable");
        return;
    }
    let recorded = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "no snapshot at {}: {error}. Run with UPDATE_SNAPSHOTS=1 to record it.",
            path.display()
        )
    });
    assert_eq!(
        recorded,
        rendered,
        "{} changed. Run with UPDATE_SNAPSHOTS=1 and review the diff.",
        path.display()
    );
}

#[cfg_attr(feature = "test-identity", allow(dead_code))]
fn check_remediation(
    name: &'static str,
    width: u16,
    height: u16,
    state: super::remediation::State,
) {
    let case = Case {
        name,
        screen: Screen::Remediation,
        theme: Theme::Dark,
        color: ColorMode::Color,
        width,
        height,
        flow: None,
        selection: None,
        run: None,
    };
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("a test terminal");
    let app = App::new(VERSION, ColorMode::Color)
        .at(Screen::Remediation, Theme::Dark)
        .with_remediation(state);
    terminal
        .draw(|frame| app.render(frame.area(), frame.buffer_mut()))
        .expect("the frame draws");
    let rendered = serialise(&case, terminal.backend().buffer());
    let path = path(name);
    if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
        std::fs::write(&path, rendered).expect("the snapshot is writable");
    } else {
        assert_eq!(
            std::fs::read_to_string(&path).expect("the snapshot is recorded"),
            rendered
        );
    }
}

fn slug(screen: Screen) -> &'static str {
    match screen {
        Screen::SignIn => "sign-in",
        Screen::Organizations => "organizations",
        Screen::Repositories => "repositories",
        Screen::Findings => "findings",
        Screen::FindingDetail => "finding-detail",
        Screen::Remediation => "remediation",
        Screen::PolicyInspector => "policy-inspector",
        Screen::PublishingBootstrap => "publishing-bootstrap",
    }
}

fn size_slug(width: u16) -> &'static str {
    if width == REFERENCE_WIDTH {
        "120x40"
    } else {
        "80x24"
    }
}

/// Every case the suite records.
///
/// Every screen is drawn at the reference and at the floor, which is the whole
/// frame proven at both sizes. The two screens that carry the most chrome and
/// the most vocabulary — sign-in, which fixes its own status line, and
/// findings, which prints the entire status vocabulary — are additionally drawn
/// in the light palette and under `NO_COLOR` at both sizes.
#[cfg_attr(feature = "test-identity", allow(dead_code))]
fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for screen in Screen::ALL {
        for (width, height) in [
            (REFERENCE_WIDTH, REFERENCE_HEIGHT),
            (FLOOR_WIDTH, FLOOR_HEIGHT),
        ] {
            cases.push(Case {
                name: Box::leak(
                    format!("{}-{}-dark", slug(screen), size_slug(width)).into_boxed_str(),
                ),
                screen,
                theme: Theme::Dark,
                color: ColorMode::Color,
                width,
                height,
                flow: None,
                selection: None,
                run: None,
            });
        }
    }
    // The five sign-in states, each at both sizes. The scan code sits alongside
    // at the reference and is withheld at the floor, so the two sizes are also
    // the two halves of that rule.
    for (name, state) in flows() {
        for (width, height) in [
            (REFERENCE_WIDTH, REFERENCE_HEIGHT),
            (FLOOR_WIDTH, FLOOR_HEIGHT),
        ] {
            cases.push(Case {
                name: Box::leak(
                    format!("sign-in-{name}-{}-dark", size_slug(width)).into_boxed_str(),
                ),
                screen: Screen::SignIn,
                theme: Theme::Dark,
                color: ColorMode::Color,
                width,
                height,
                flow: Some(state.clone()),
                selection: None,
                run: None,
            });
        }
    }
    // The awaiting state is the one that draws a scan code, so it is the one
    // whose light palette and colourless renderings are worth recording.
    let awaiting = flows()
        .into_iter()
        .find(|(name, _)| *name == "awaiting")
        .map(|(_, state)| state)
        .expect("the awaiting state is one of the five");
    cases.push(Case {
        name: "sign-in-awaiting-120x40-light",
        screen: Screen::SignIn,
        theme: Theme::Light,
        color: ColorMode::Color,
        width: REFERENCE_WIDTH,
        height: REFERENCE_HEIGHT,
        flow: Some(awaiting.clone()),
        selection: None,
        run: None,
    });
    cases.push(Case {
        name: "sign-in-awaiting-120x40-no-color",
        screen: Screen::SignIn,
        theme: Theme::Dark,
        color: ColorMode::NoColor,
        width: REFERENCE_WIDTH,
        height: REFERENCE_HEIGHT,
        flow: Some(awaiting),
        selection: None,
        run: None,
    });
    for screen in [Screen::SignIn, Screen::Findings] {
        for (width, height) in [
            (REFERENCE_WIDTH, REFERENCE_HEIGHT),
            (FLOOR_WIDTH, FLOOR_HEIGHT),
        ] {
            cases.push(Case {
                name: Box::leak(
                    format!("{}-{}-light", slug(screen), size_slug(width)).into_boxed_str(),
                ),
                screen,
                theme: Theme::Light,
                color: ColorMode::Color,
                width,
                height,
                flow: None,
                selection: None,
                run: None,
            });
            cases.push(Case {
                name: Box::leak(
                    format!("{}-{}-no-color", slug(screen), size_slug(width)).into_boxed_str(),
                ),
                screen,
                theme: Theme::Dark,
                color: ColorMode::NoColor,
                width,
                height,
                flow: None,
                selection: None,
                run: None,
            });
        }
    }
    // The four selection readings the definition of done names: an empty
    // installation list, a scoped installation, a user account beside an
    // organization, and a filtered repository table. Each at both sizes,
    // because the table and the three causes are what the floor squeezes.
    for (width, height) in [
        (REFERENCE_WIDTH, REFERENCE_HEIGHT),
        (FLOOR_WIDTH, FLOOR_HEIGHT),
    ] {
        for (name, screen, selection) in [
            (
                "organizations-empty",
                Screen::Organizations,
                Selection {
                    catalogue: Catalogue::of(Vec::new()),
                    moved: 0,
                    filter: "",
                },
            ),
            (
                "organizations-reachable",
                Screen::Organizations,
                Selection {
                    catalogue: catalogue(),
                    moved: 0,
                    filter: "",
                },
            ),
            (
                "organizations-scoped-user-account",
                Screen::Organizations,
                Selection {
                    catalogue: catalogue(),
                    moved: 1,
                    filter: "",
                },
            ),
            (
                "repositories-listed",
                Screen::Repositories,
                Selection {
                    catalogue: catalogue(),
                    moved: 0,
                    filter: "",
                },
            ),
            (
                "repositories-filtered",
                Screen::Repositories,
                Selection {
                    catalogue: catalogue(),
                    moved: 0,
                    filter: "et",
                },
            ),
            (
                "repositories-prefix",
                Screen::Repositories,
                Selection {
                    catalogue: prefix(),
                    moved: 0,
                    filter: "",
                },
            ),
            (
                "organizations-prefix",
                Screen::Organizations,
                Selection {
                    catalogue: prefix(),
                    moved: 0,
                    filter: "",
                },
            ),
        ] {
            cases.push(Case {
                name: Box::leak(format!("{name}-{}-dark", size_slug(width)).into_boxed_str()),
                screen,
                theme: Theme::Dark,
                color: ColorMode::Color,
                width,
                height,
                flow: None,
                selection: Some(selection),
                run: None,
            });
        }
    }
    cases.extend(queues());
    cases.extend(readings());
    cases
}

/// The two screens that answer why a run says what it says.
///
/// The three detail kinds are recorded because they are the three that have to
/// read differently and the ways of getting them wrong all look like each
/// other: a suppression that reads as absent, an error that reads as a failure,
/// a failure that reads as an incomplete run. Each is drawn at both sizes and
/// without colour, because none of the three is told apart by hue.
#[cfg_attr(feature = "test-identity", allow(dead_code))]
fn readings() -> Vec<Case> {
    use super::findings::fixture;

    let mut cases = Vec::new();
    // Every case starts on the queue and is driven to the screen by the keys
    // the specification binds, so a recorded screen is one the interface can
    // actually be reached on rather than one the suite placed the operator in.
    for (name, run) in [
        // The queue's first row is the settings failure.
        (
            "finding-detail-fail",
            Run::of(fixture::mixed()).driven(1, "\n"),
        ),
        // Group seven is the standing debt, and its row is the suppression.
        (
            "finding-detail-suppressed",
            Run::of(fixture::mixed()).driven(13, "\n"),
        ),
        // The run that fell short carries the errored rule in group five.
        (
            "finding-detail-error",
            Run::of(fixture::incomplete()).driven(7, "\n"),
        ),
        (
            "policy-inspector-read",
            Run::of(fixture::mixed()).driven(0, "p"),
        ),
    ] {
        for (theme, color, slug) in [
            (Theme::Dark, ColorMode::Color, "dark"),
            (Theme::Dark, ColorMode::NoColor, "no-color"),
        ] {
            for (width, height) in [
                (REFERENCE_WIDTH, REFERENCE_HEIGHT),
                (FLOOR_WIDTH, FLOOR_HEIGHT),
            ] {
                cases.push(Case {
                    name: Box::leak(format!("{name}-{}-{slug}", size_slug(width)).into_boxed_str()),
                    screen: Screen::Findings,
                    theme,
                    color,
                    width,
                    height,
                    flow: None,
                    selection: None,
                    run: Some(run.clone()),
                });
            }
        }
    }
    cases
}

/// The findings screen with a run on it.
///
/// The work queue is the screen the whole interface exists for, so every
/// reading the definition of done names is recorded: both sizes, both palettes,
/// no colour at all, a run that fell short, a repository with nothing left to
/// close, a group collapsed and a group expanded, and the flat lookup view.
#[cfg_attr(feature = "test-identity", allow(dead_code))]
fn queues() -> Vec<Case> {
    use super::findings::fixture;

    let mut cases = Vec::new();
    // The default reading, in both palettes and without colour, at both sizes.
    for (theme, color, slug) in [
        (Theme::Dark, ColorMode::Color, "dark"),
        (Theme::Light, ColorMode::Color, "light"),
        (Theme::Dark, ColorMode::NoColor, "no-color"),
    ] {
        for (width, height) in [
            (REFERENCE_WIDTH, REFERENCE_HEIGHT),
            (FLOOR_WIDTH, FLOOR_HEIGHT),
        ] {
            cases.push(Case {
                name: Box::leak(
                    format!("findings-queue-{}-{slug}", size_slug(width)).into_boxed_str(),
                ),
                screen: Screen::Findings,
                theme,
                color,
                width,
                height,
                flow: None,
                selection: None,
                run: Some(Run::of(fixture::mixed())),
            });
        }
    }
    // The readings that differ by what the run held or where the operator
    // moved. The aligned group opens collapsed, so expanding it is a keystroke
    // on the last heading in the queue.
    for (name, run) in [
        ("findings-incomplete", Run::of(fixture::incomplete())),
        ("findings-aligned", Run::of(fixture::aligned())),
        (
            "findings-collapsed",
            Run::of(fixture::mixed()).driven(0, " "),
        ),
        (
            "findings-expanded",
            Run::of(fixture::mixed()).driven(14, " "),
        ),
        (
            "findings-filtered",
            Run::of(fixture::mixed()).driven(0, "f"),
        ),
        ("findings-lookup", Run::of(fixture::mixed()).driven(0, "l")),
    ] {
        for (width, height) in [
            (REFERENCE_WIDTH, REFERENCE_HEIGHT),
            (FLOOR_WIDTH, FLOOR_HEIGHT),
        ] {
            cases.push(Case {
                name: Box::leak(format!("{name}-{}-dark", size_slug(width)).into_boxed_str()),
                screen: Screen::Findings,
                theme: Theme::Dark,
                color: ColorMode::Color,
                width,
                height,
                flow: None,
                selection: None,
                run: Some(run.clone()),
            });
        }
    }
    // A declared reason longer than the floor can carry, at both widths. The
    // floor withholds it with a notice rather than half printing it; the
    // reference takes a second line and carries it whole. The pair is the
    // monotonic rule as a reading rather than as an assertion: widening a
    // terminal adds the fact and never takes one away.
    for (width, height) in [
        (REFERENCE_WIDTH, REFERENCE_HEIGHT),
        (FLOOR_WIDTH, FLOOR_HEIGHT),
    ] {
        cases.push(Case {
            name: Box::leak(
                format!("findings-withheld-fact-{}-dark", size_slug(width)).into_boxed_str(),
            ),
            screen: Screen::Findings,
            theme: Theme::Dark,
            color: ColorMode::Color,
            width,
            height,
            flow: None,
            selection: None,
            run: Some(Run::of(fixture::long_fact())),
        });
    }
    cases
}

/// The recorded files are of the shipped build, which names Airlock Admin on
/// the sign-in screen. A test build names Airlock Test there — deliberately, so
/// an operator can never be unsure which identity a development binary is bound
/// to — so the comparison is skipped rather than recorded twice. What that build
/// asserts instead is below.
#[cfg(not(feature = "test-identity"))]
#[test]
fn the_frame_renders_as_recorded() {
    for case in cases() {
        check(&case);
    }
}

#[cfg(feature = "test-identity")]
#[test]
fn a_test_build_names_the_test_identity_on_the_screen() {
    let rendered = characters(&Case {
        name: "comparison",
        screen: Screen::SignIn,
        theme: Theme::Dark,
        color: ColorMode::Color,
        width: REFERENCE_WIDTH,
        height: REFERENCE_HEIGHT,
        flow: None,
        selection: None,
        run: None,
    });
    assert!(rendered.contains("Airlock Test"), "{rendered}");
    assert!(!rendered.contains("Airlock Admin"), "{rendered}");
}

/// The character grid below the header, which is the whole reading.
///
/// The header row is excluded because it names the palette in force, which is
/// the one thing that legitimately differs between the two. That the header
/// does not otherwise move is asserted where the header is built.
fn reading(case: &Case) -> String {
    characters(case)
        .lines()
        .skip(1)
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_reading_is_the_same_text_in_both_palettes_and_without_colour() {
    for screen in Screen::ALL {
        for (width, height) in [
            (REFERENCE_WIDTH, REFERENCE_HEIGHT),
            (FLOOR_WIDTH, FLOOR_HEIGHT),
        ] {
            // The two selection screens are compared populated as well as
            // empty: they are the ones that draw a table, and a table is where
            // a palette could quietly become the thing carrying a column.
            let selection =
                matches!(screen, Screen::Organizations | Screen::Repositories).then(|| Selection {
                    catalogue: catalogue(),
                    moved: 0,
                    filter: "",
                });
            // The findings screen is compared with a run on it as well as
            // empty: it is the screen that carries the most meaning in colour,
            // and a queue is where a palette could quietly become the thing
            // carrying a group.
            let run =
                (screen == Screen::Findings).then(|| Run::of(super::findings::fixture::mixed()));
            let case = |theme, color| Case {
                name: "comparison",
                screen,
                theme,
                color,
                width,
                height,
                flow: None,
                selection: selection.clone(),
                run: run.clone(),
            };
            let dark = reading(&case(Theme::Dark, ColorMode::Color));
            let light = reading(&case(Theme::Light, ColorMode::Color));
            let mono = reading(&case(Theme::Dark, ColorMode::NoColor));
            assert_eq!(dark, light, "{screen:?} at {width}x{height}");
            assert_eq!(dark, mono, "{screen:?} at {width}x{height}");
        }
    }
}

/// The awaiting state, which is the one that draws a scan code.
fn awaiting_case(theme: Theme, color: ColorMode) -> Case {
    Case {
        name: "comparison",
        screen: Screen::SignIn,
        theme,
        color,
        width: REFERENCE_WIDTH,
        height: REFERENCE_HEIGHT,
        selection: None,
        run: None,
        flow: flows()
            .into_iter()
            .find(|(name, _)| *name == "awaiting")
            .map(|(_, state)| state),
    }
}

#[test]
fn a_scan_code_reads_the_same_in_both_palettes_and_is_withheld_without_colour() {
    let dark = characters(&awaiting_case(Theme::Dark, ColorMode::Color));
    let light = characters(&awaiting_case(Theme::Light, ColorMode::Color));
    assert_eq!(
        reading(&awaiting_case(Theme::Dark, ColorMode::Color)),
        reading(&awaiting_case(Theme::Light, ColorMode::Color)),
        "the code is painted, not themed"
    );
    assert!(dark.contains('\u{2580}') && light.contains('\u{2580}'));

    // Without colour it cannot paint its own field, so it is withheld and the
    // screen says which of the two facts is missing.
    let mono = characters(&awaiting_case(Theme::Dark, ColorMode::NoColor));
    assert!(
        !mono.contains('\u{2580}'),
        "a code that cannot be painted is not drawn"
    );
    assert!(mono.contains("NO_COLOR"), "{mono}");
}

#[test]
fn the_two_palettes_never_paint_a_screen_the_same_way() {
    for screen in Screen::ALL {
        let case = |theme| Case {
            name: "comparison",
            screen,
            theme,
            color: ColorMode::Color,
            width: REFERENCE_WIDTH,
            height: REFERENCE_HEIGHT,
            flow: None,
            selection: None,
            run: None,
        };
        assert_ne!(
            legend(&case(Theme::Dark)),
            legend(&case(Theme::Light)),
            "{screen:?}"
        );
    }
}

#[test]
fn no_color_emits_no_colour_at_all() {
    for screen in Screen::ALL {
        for (width, height) in [
            (REFERENCE_WIDTH, REFERENCE_HEIGHT),
            (FLOOR_WIDTH, FLOOR_HEIGHT),
        ] {
            let entries = legend(&Case {
                name: "comparison",
                screen,
                theme: Theme::Dark,
                color: ColorMode::NoColor,
                width,
                height,
                flow: None,
                selection: None,
                run: None,
            });
            for entry in &entries {
                assert!(
                    entry.contains("fg=reset") && entry.contains("bg=reset"),
                    "{screen:?} at {width}x{height} emitted {entry}"
                );
            }
        }
    }
}

#[test]
fn the_whole_vocabulary_is_legible_at_the_floor_without_colour() {
    // The acceptance reading: at 80x24, with no colour at all, every one of the
    // nine statuses is on screen, each in its own lane.
    let rendered = characters(&Case {
        name: "comparison",
        screen: Screen::Findings,
        theme: Theme::Dark,
        color: ColorMode::NoColor,
        width: FLOOR_WIDTH,
        height: FLOOR_HEIGHT,
        flow: None,
        selection: None,
        run: None,
    });
    for status in airlock_core::findings::Status::ALL {
        assert!(
            rendered.contains(super::lane::glyph_of(*status)),
            "{status:?} is not on screen at the floor"
        );
        assert!(
            rendered.contains(status.code()),
            "{status:?} is unnamed at the floor"
        );
    }
}

#[test]
fn a_terminal_under_the_floor_is_told_so_rather_than_drawn_into() {
    let rendered = render(&Case {
        name: "comparison",
        screen: Screen::Findings,
        theme: Theme::Dark,
        color: ColorMode::Color,
        width: 60,
        height: 20,
        flow: None,
        selection: None,
        run: None,
    });
    assert!(rendered.contains("TERMINAL TOO SMALL"), "{rendered}");
    assert!(!rendered.contains("STATUS VOCABULARY"), "{rendered}");
}

fn section(rendered: &str, marker: &str) -> String {
    let start = rendered
        .find(marker)
        .map(|index| index + marker.len())
        .expect("the section is present");
    let rest = &rendered[start..];
    let end = rest.find("--- ").unwrap_or(rest.len());
    rest[..end].to_string()
}

fn characters(case: &Case) -> String {
    section(&render(case), "--- text ---\n")
}

fn legend(case: &Case) -> Vec<String> {
    section(&render(case), "--- legend ---\n")
        .lines()
        .map(str::to_string)
        .collect()
}

#[test]
#[cfg(not(feature = "test-identity"))]
fn remediation_input_and_result_frames_match_recordings() {
    use super::remediation::{Input, Item, State};
    use crate::admin::remediation::{ObservedStatus, Step, Transcript};

    let item = |code: &str, input| Item {
        rule: "REPO-SAMPLE-01".to_owned(),
        remediation: code.to_owned(),
        change: "Apply the observed settings change.".to_owned(),
        reversible: true,
        input,
    };
    let frames = [
        (
            "remediation-rename-input-120x40-dark",
            State::confirm(
                "generic-owner".to_owned(),
                "sample-repository".to_owned(),
                vec![item(
                    "rename-repository-kebab",
                    Input::Text {
                        draft: "sample-repository".to_owned(),
                        required_prefix: None,
                        error: None,
                    },
                )],
            ),
        ),
        (
            "remediation-ruleset-choice-120x40-dark",
            State::confirm(
                "generic-owner".to_owned(),
                "sample-repository".to_owned(),
                vec![item(
                    "attach-org-rulesets",
                    Input::Choice {
                        values: vec![
                            "41 — protected branches".to_owned(),
                            "create — Airlock default branch".to_owned(),
                        ],
                        selected: 0,
                        empty: String::new(),
                    },
                )],
            ),
        ),
        (
            "remediation-transfer-120x40-dark",
            State::confirm(
                "generic-owner".to_owned(),
                "sample-repository".to_owned(),
                vec![item(
                    "transfer-repository",
                    Input::Transfer {
                        destinations: vec!["destination-owner".to_owned()],
                        selected: 0,
                        typed_name: "sample-repository".to_owned(),
                    },
                )],
            ),
        ),
        (
            "remediation-variable-secret-deferral-120x40-dark",
            State::confirm(
                "generic-owner".to_owned(),
                "sample-repository".to_owned(),
                vec![item(
                    "rename-app-credentials",
                    Input::VariableRename {
                        names: vec!["LEGACY_NAME".to_owned()],
                        selected: 0,
                        draft: "CURRENT_NAME".to_owned(),
                        notice: super::remediation::SECRET_DEFERRAL_NOTICE.to_owned(),
                        error: None,
                    },
                )],
            ),
        ),
    ];
    for (name, state) in frames {
        check_remediation(name, REFERENCE_WIDTH, REFERENCE_HEIGHT, state.clone());
        let floor_name = Box::leak(name.replace("120x40", "80x24").into_boxed_str());
        check_remediation(floor_name, FLOOR_WIDTH, FLOOR_HEIGHT, state);
    }
    let mut creation = State::confirm(
        "generic-owner".to_owned(),
        "sample-repository".to_owned(),
        vec![item(
            "attach-org-rulesets",
            Input::Choice {
                values: vec!["create — Airlock default branch".to_owned()],
                selected: 0,
                empty: String::new(),
            },
        )],
    );
    assert!(creation.input_key(KeyCode::Enter));
    check_remediation(
        "remediation-ruleset-confirm-120x40-dark",
        REFERENCE_WIDTH,
        REFERENCE_HEIGHT,
        creation.clone(),
    );
    check_remediation(
        "remediation-ruleset-confirm-80x24-dark",
        FLOOR_WIDTH,
        FLOOR_HEIGHT,
        creation,
    );
    let mut attachment = State::confirm(
        "generic-owner".to_owned(),
        "sample-repository".to_owned(),
        vec![item(
            "attach-org-rulesets",
            Input::Choice {
                values: vec!["41 — protected branches".to_owned()],
                selected: 0,
                empty: String::new(),
            },
        )],
    );
    assert!(attachment.input_key(KeyCode::Enter));
    check_remediation(
        "remediation-ruleset-attach-confirm-120x40-dark",
        REFERENCE_WIDTH,
        REFERENCE_HEIGHT,
        attachment.clone(),
    );
    check_remediation(
        "remediation-ruleset-attach-confirm-80x24-dark",
        FLOOR_WIDTH,
        FLOOR_HEIGHT,
        attachment,
    );

    let mut complete = State::confirm(
        "generic-owner".to_owned(),
        "sample-repository".to_owned(),
        vec![item("disable-merge-commits", Input::None)],
    );
    let _ = complete.take_confirmation();
    complete.complete(Transcript {
        rule: "REPO-SAMPLE-01".to_owned(),
        remediation: "disable-merge-commits".to_owned(),
        proposed_change: "disable merge commits".to_owned(),
        steps: vec![Step {
            detail: "re-observation reports pass".to_owned(),
            elapsed: std::time::Duration::from_millis(25),
            succeeded: true,
        }],
        observed: ObservedStatus::Pass,
        undo: None,
    });
    check_remediation(
        "remediation-complete-120x40-dark",
        REFERENCE_WIDTH,
        REFERENCE_HEIGHT,
        complete,
    );
    let mut floor_complete = State::confirm(
        "generic-owner".to_owned(),
        "sample-repository".to_owned(),
        vec![item("disable-merge-commits", Input::None)],
    );
    let _ = floor_complete.take_confirmation();
    floor_complete.complete(Transcript {
        rule: "REPO-SAMPLE-01".to_owned(),
        remediation: "disable-merge-commits".to_owned(),
        proposed_change: "disable merge commits".to_owned(),
        steps: vec![Step {
            detail: "re-observation reports pass".to_owned(),
            elapsed: std::time::Duration::from_millis(25),
            succeeded: true,
        }],
        observed: ObservedStatus::Pass,
        undo: None,
    });
    check_remediation(
        "remediation-complete-80x24-dark",
        FLOOR_WIDTH,
        FLOOR_HEIGHT,
        floor_complete,
    );
}
