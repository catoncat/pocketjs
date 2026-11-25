//! Pure-Rust QR code matrix generator (`Vec<Vec<bool>>`) for Tailscale login URLs
//! and 5-minute ephemeral pairing links on the 320x170 CardputerZero display.

use qrcode::{Color, EcLevel, QrCode};

/// Encodes `content` into a square boolean matrix (`true` = dark module, `false` = light).
/// Uses low error correction (`EcLevel::L`) first so URLs stay compact enough to render
/// at crisp integer 2x2 or 3x3 pixel modules inside a 116x116 panel box.
pub fn encode_matrix(content: &str) -> Option<Vec<Vec<bool>>> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return None;
    }
    let code = QrCode::with_error_correction_level(trimmed.as_bytes(), EcLevel::L)
        .or_else(|_| QrCode::new(trimmed.as_bytes()))
        .ok()?;
    let width = code.width();
    let colors = code.into_colors();
    let mut rows = Vec::with_capacity(width);
    for y in 0..width {
        let start = y * width;
        let row = colors[start..start + width]
            .iter()
            .map(|&c| c == Color::Dark)
            .collect();
        rows.push(row);
    }
    Some(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_square_matrix_with_finder_patterns() {
        let matrix = encode_matrix("https://login.tailscale.com/a/rexzero01").unwrap();
        let n = matrix.len();
        assert!((21..=49).contains(&n), "unexpected QR size {n}");
        assert!(matrix.iter().all(|row| row.len() == n));
        // Top-left 7x7 finder pattern outer corners and center are always dark.
        assert!(matrix[0][0] && matrix[0][6] && matrix[6][0] && matrix[6][6] && matrix[3][3]);
        // Empty input yields None.
        assert!(encode_matrix("   ").is_none());
    }
}
