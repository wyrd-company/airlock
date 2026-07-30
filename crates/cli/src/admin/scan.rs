//! The scan code on the sign-in screen.
//!
//! It is an accelerator and never the only way in. GitHub's device flow offers
//! no address that carries the code, so the code is always typed by hand and is
//! always present as legible text; this encodes the address alone.
//!
//! Two properties matter more than the encoding. The code paints its own light
//! field and a four-module quiet zone rather than inheriting the terminal
//! background, so it scans identically on both palettes. And it is withheld
//! rather than clipped when there is not room for all of it, because a code
//! that cannot be scanned is worse than an address the operator types.

use qrcode::types::Color as Module;
use qrcode::{EcLevel, QrCode};

/// The quiet zone, in modules, on every side.
///
/// Four is what the specification for the symbology requires, and a scan code
/// drawn without it fails against a busy background.
pub const QUIET_ZONE: usize = 4;

/// Two module rows are drawn per text row, using the upper half block.
const HALF_BLOCK: &str = "\u{2580}";

/// One rendered scan code: a grid of module rows, and the size it needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanCode {
    /// The rows, each a run of module colours, light field and quiet zone
    /// included. Every row is [`ScanCode::columns`] long.
    rows: Vec<Vec<bool>>,
}

/// A cell of a drawn scan code: what the upper half of the cell is, and the
/// lower.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cell {
    /// Whether the upper half-module is dark.
    pub upper_dark: bool,
    /// Whether the lower half-module is dark.
    pub lower_dark: bool,
}

impl ScanCode {
    /// Encode an address.
    ///
    /// # Errors
    ///
    /// Returns an error when the address will not fit any symbol version, which
    /// for a device-flow verification address it never does. The failure is
    /// returned rather than unwrapped so a change of address cannot take the
    /// screen down.
    pub fn encode(address: &str) -> Result<Self, qrcode::types::QrError> {
        // The lowest correction level the symbology has. A scan code on a
        // screen is read from a hand's distance with nothing occluding it; the
        // higher levels buy resilience this case does not need and pay for it
        // in modules, which is width the floor does not have.
        let code = QrCode::with_error_correction_level(address, EcLevel::L)?;
        let width = code.width();
        let colors = code.into_colors();
        let mut rows = Vec::with_capacity(width + QUIET_ZONE * 2);
        let light_row = vec![false; width + QUIET_ZONE * 2];
        for _ in 0..QUIET_ZONE {
            rows.push(light_row.clone());
        }
        for y in 0..width {
            let mut row = Vec::with_capacity(width + QUIET_ZONE * 2);
            row.extend(std::iter::repeat_n(false, QUIET_ZONE));
            for x in 0..width {
                row.push(colors[y * width + x] == Module::Dark);
            }
            row.extend(std::iter::repeat_n(false, QUIET_ZONE));
            rows.push(row);
        }
        for _ in 0..QUIET_ZONE {
            rows.push(light_row.clone());
        }
        Ok(Self { rows })
    }

    /// How many terminal columns the code occupies.
    #[must_use]
    pub fn columns(&self) -> usize {
        self.rows.first().map_or(0, Vec::len)
    }

    /// How many terminal rows the code occupies.
    ///
    /// Two module rows are drawn per text row, so a code with an odd number of
    /// module rows is padded with a light row rather than losing one.
    #[must_use]
    pub fn lines(&self) -> usize {
        self.rows.len().div_ceil(2)
    }

    /// The cells of one text row.
    #[must_use]
    pub fn row(&self, line: usize) -> Vec<Cell> {
        let upper = self.rows.get(line * 2);
        let lower = self.rows.get(line * 2 + 1);
        let width = self.columns();
        (0..width)
            .map(|x| Cell {
                upper_dark: upper.is_some_and(|row| row[x]),
                lower_dark: lower.is_some_and(|row| row[x]),
            })
            .collect()
    }
}

/// The glyph every cell of a scan code is drawn with.
///
/// One glyph, two colours: the upper half-module is the foreground and the
/// lower is the background. Both are painted, so neither inherits the palette.
#[must_use]
pub const fn glyph() -> &'static str {
    HALF_BLOCK
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GitHub's device-flow address, which is the only thing this ever encodes.
    const ADDRESS: &str = "https://github.com/login/device";

    fn code() -> ScanCode {
        ScanCode::encode(ADDRESS).expect("the device address encodes")
    }

    #[test]
    fn the_device_address_occupies_the_width_the_specification_states() {
        // 33 columns is what the specification budgets, and it is why the code
        // is withheld at the 80-column floor rather than drawn beside the code.
        assert_eq!(code().columns(), 33);
        assert_eq!(code().lines(), 17);
    }

    #[test]
    fn the_quiet_zone_is_light_on_every_side() {
        let code = code();
        let columns = code.columns();
        for line in 0..QUIET_ZONE / 2 {
            for cell in code.row(line) {
                assert!(!cell.upper_dark && !cell.lower_dark, "top quiet zone");
            }
        }
        for line in code.lines() - QUIET_ZONE / 2..code.lines() {
            for cell in code.row(line) {
                assert!(!cell.upper_dark && !cell.lower_dark, "bottom quiet zone");
            }
        }
        for line in 0..code.lines() {
            let row = code.row(line);
            for cell in row.iter().take(QUIET_ZONE) {
                assert!(!cell.upper_dark && !cell.lower_dark, "left quiet zone");
            }
            for cell in row.iter().skip(columns - QUIET_ZONE) {
                assert!(!cell.upper_dark && !cell.lower_dark, "right quiet zone");
            }
        }
    }

    #[test]
    fn the_symbol_itself_is_drawn_between_the_quiet_zones() {
        let code = code();
        let dark = (0..code.lines())
            .flat_map(|line| code.row(line))
            .filter(|cell| cell.upper_dark || cell.lower_dark)
            .count();
        assert!(dark > 100, "a symbol with {dark} dark cells is not one");
    }

    #[test]
    fn every_row_is_the_same_width() {
        let code = code();
        for line in 0..code.lines() {
            assert_eq!(code.row(line).len(), code.columns(), "line {line}");
        }
    }

    #[test]
    fn the_encoding_is_stable_for_the_same_address() {
        assert_eq!(code(), code());
    }

    #[test]
    fn an_address_too_long_to_encode_is_an_error_rather_than_a_panic() {
        let absurd = "x".repeat(8000);
        assert!(ScanCode::encode(&absurd).is_err());
    }
}
