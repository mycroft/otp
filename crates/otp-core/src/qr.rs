//! QR codes: decoding from images and screenshots, and encoding for display or export.

use std::fs::OpenOptions;
use std::io::{BufWriter, ErrorKind};
use std::path::Path;
use std::process::{Command, Stdio};

use image::{DynamicImage, GrayImage, ImageFormat, Luma};
use qrcode::{EcLevel, QrCode};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Default screenshot command: select a screen area with grimshot (Sway/wlroots).
/// `{file}` is replaced by the path of the PNG file to write.
pub const DEFAULT_CAPTURE_COMMAND: &[&str] = &["grimshot", "save", "area", "{file}"];

/// Decodes every QR code found in an image.
pub fn decode_image(image: &DynamicImage) -> Vec<Zeroizing<String>> {
    let gray = image.to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(
        gray.width() as usize,
        gray.height() as usize,
        |x, y| gray.get_pixel(x as u32, y as u32)[0],
    );
    prepared
        .detect_grids()
        .into_iter()
        .filter_map(|grid| grid.decode().ok())
        .map(|(_, content)| Zeroizing::new(content))
        .collect()
}

/// Decodes every QR code found in an image file.
pub fn decode_file(path: &Path) -> Result<Vec<Zeroizing<String>>> {
    let image = image::open(path)
        .map_err(|e| Error::Qr(format!("cannot read image {}: {e}", path.display())))?;
    Ok(decode_image(&image))
}

/// Picks the single `otpauth://` URI among decoded QR code contents.
pub fn find_otpauth_uri(contents: Vec<Zeroizing<String>>) -> Result<Zeroizing<String>> {
    if contents.is_empty() {
        return Err(Error::Qr("no QR code found".into()));
    }
    if contents.iter().any(|c| c.starts_with("otpauth-migration:")) {
        return Err(Error::Qr(
            "found a Google Authenticator export (otpauth-migration://), which is not supported"
                .into(),
        ));
    }
    let mut uris: Vec<_> = contents
        .into_iter()
        .filter(|c| {
            c.trim_start()
                .to_ascii_lowercase()
                .starts_with("otpauth://")
        })
        .collect();
    match uris.len() {
        0 => Err(Error::Qr(
            "the QR code does not contain an otpauth:// URI".into(),
        )),
        1 => Ok(uris.remove(0)),
        n => Err(Error::Qr(format!(
            "found {n} otpauth QR codes, select an area containing only one"
        ))),
    }
}

/// Runs a screenshot command and decodes the QR codes in the captured image.
///
/// Arguments equal to `{file}` are replaced with the output file path; if there is none,
/// the path is appended as the last argument.
pub fn capture<S: AsRef<str>>(command: &[S]) -> Result<Vec<Zeroizing<String>>> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| Error::Capture("capture command is empty".into()))?;
    let program = program.as_ref();
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("capture.png");
    // Keep the tool's output off the terminal (a TUI may be drawn there); its last
    // stderr line explains a failure.
    let output = command_with_file(program, args, &file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                Error::Capture(format!("{program} not found"))
            } else {
                Error::Io(e)
            }
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Capture(
            match stderr.lines().rev().find(|l| !l.trim().is_empty()) {
                Some(detail) => format!("{program} failed: {}", detail.trim()),
                None => format!("{program} failed ({})", output.status),
            },
        ));
    }
    match std::fs::metadata(&file) {
        Ok(meta) if meta.len() > 0 => decode_file(&file),
        _ => Err(Error::Capture(
            "no screenshot was taken (selection cancelled?)".into(),
        )),
    }
}

/// Builds `program args...`, replacing `{file}` in the arguments with `file`, or appending
/// `file` when no argument contains the placeholder.
fn command_with_file<S: AsRef<str>>(program: &str, args: &[S], file: &Path) -> Command {
    let file_arg = file.to_string_lossy();
    let mut cmd = Command::new(program);
    let mut has_placeholder = false;
    for arg in args {
        let arg = arg.as_ref();
        if arg.contains("{file}") {
            has_placeholder = true;
            cmd.arg(arg.replace("{file}", &file_arg));
        } else {
            cmd.arg(arg);
        }
    }
    if !has_placeholder {
        cmd.arg(file);
    }
    cmd
}

/// The modules of an encoded QR code.
pub struct QrMatrix {
    width: usize,
    dark: Vec<bool>,
}

impl QrMatrix {
    /// Encodes `text` with medium error correction, for images that may be printed.
    pub fn encode(text: &str) -> Result<Self> {
        Self::with_level(text, EcLevel::M)
    }

    /// Encodes `text` with low error correction: the smallest code, for screens.
    pub fn encode_compact(text: &str) -> Result<Self> {
        Self::with_level(text, EcLevel::L)
    }

    fn with_level(text: &str, level: EcLevel) -> Result<Self> {
        let code = QrCode::with_error_correction_level(text.as_bytes(), level)
            .map_err(|e| Error::Qr(format!("cannot encode: {e}")))?;
        Ok(QrMatrix {
            width: code.width(),
            dark: code
                .to_colors()
                .into_iter()
                .map(|color| color == qrcode::Color::Dark)
                .collect(),
        })
    }

    /// Number of modules per side, without quiet zone.
    pub fn width(&self) -> usize {
        self.width
    }

    /// Whether the module at (x, y) is dark; anything outside the code (the quiet zone)
    /// is light.
    pub fn is_dark(&self, x: isize, y: isize) -> bool {
        let range = 0..self.width as isize;
        range.contains(&x) && range.contains(&y) && self.dark[y as usize * self.width + x as usize]
    }

    /// Renders the code with `quiet` light modules around it, two module rows per line:
    /// `█` both dark, `▀` top dark, `▄` bottom dark, space both light. Display it dark on
    /// light: black foreground, white background.
    pub fn half_block_lines(&self, quiet: usize) -> Vec<String> {
        let (start, end) = (-(quiet as isize), (self.width + quiet) as isize);
        (start..end)
            .step_by(2)
            .map(|y| {
                (start..end)
                    .map(|x| match (self.is_dark(x, y), self.is_dark(x, y + 1)) {
                        (true, true) => '█',
                        (true, false) => '▀',
                        (false, true) => '▄',
                        (false, false) => ' ',
                    })
                    .collect()
            })
            .collect()
    }

    /// Renders the code as an image, `scale` pixels per module, with a `quiet` zone.
    pub fn to_image(&self, scale: u32, quiet: u32) -> GrayImage {
        let size = (self.width as u32 + 2 * quiet) * scale;
        GrayImage::from_fn(size, size, |x, y| {
            let module = |p: u32| (p / scale) as isize - quiet as isize;
            Luma([if self.is_dark(module(x), module(y)) {
                0
            } else {
                255
            }])
        })
    }
}

/// Writes `text` as a QR code PNG. The file must not exist yet; it is created with mode
/// 0600 since QR codes of otpauth URIs contain the secret.
pub fn write_png(text: &str, path: &Path) -> Result<()> {
    let image = QrMatrix::encode(text)?.to_image(8, 4);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let file = options.open(path)?;
    image
        .write_to(&mut BufWriter::new(file), ImageFormat::Png)
        .map_err(|e| Error::Qr(format!("cannot write {}: {e}", path.display())))
}

/// Shows `text` as a QR code with an external viewer (e.g. `["chafa", "{file}"]`), given a
/// temporary PNG that is deleted once the viewer exits.
pub fn view<S: AsRef<str>>(command: &[S], text: &str) -> Result<()> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| Error::Viewer("viewer command is empty".into()))?;
    let program = program.as_ref();
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("qrcode.png");
    write_png(text, &file)?;
    let status = command_with_file(program, args, &file)
        .status()
        .map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                Error::Viewer(format!("{program} not found"))
            } else {
                Error::Io(e)
            }
        })?;
    if !status.success() {
        return Err(Error::Viewer(format!("{program} failed ({status})")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{GrayImage, Luma};

    fn render(text: &str) -> DynamicImage {
        let code = qrcode::QrCode::new(text.as_bytes()).unwrap();
        let width = code.width();
        let colors = code.to_colors();
        let (scale, border) = (8, 4);
        let size = ((width + 2 * border) * scale) as u32;
        let image = GrayImage::from_fn(size, size, |x, y| {
            let (mx, my) = (x as usize / scale, y as usize / scale);
            let dark = (border..border + width).contains(&mx)
                && (border..border + width).contains(&my)
                && colors[(my - border) * width + (mx - border)] == qrcode::Color::Dark;
            Luma([if dark { 0 } else { 255 }])
        });
        DynamicImage::ImageLuma8(image)
    }

    const URI: &str = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example";

    #[test]
    fn decodes_generated_qr_code() {
        let found = decode_image(&render(URI));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].as_str(), URI);
    }

    #[test]
    fn decodes_png_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qr.png");
        render(URI).save(&path).unwrap();
        let uri = find_otpauth_uri(decode_file(&path).unwrap()).unwrap();
        assert_eq!(uri.as_str(), URI);
    }

    #[test]
    fn capture_runs_command_with_placeholder() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("qr.png");
        render(URI).save(&source).unwrap();
        let source = source.to_str().unwrap();
        let found = capture(&["cp", source, "{file}"]).unwrap();
        assert_eq!(find_otpauth_uri(found).unwrap().as_str(), URI);
        // Without a placeholder the file path is appended.
        let found = capture(&["cp", source]).unwrap();
        assert_eq!(find_otpauth_uri(found).unwrap().as_str(), URI);
    }

    #[test]
    fn capture_reports_failures() {
        assert!(matches!(capture(&["false"]), Err(Error::Capture(_))));
        // The tool's own explanation is reported.
        let error = capture(&["sh", "-c", "echo 'slurp: selection cancelled' >&2; exit 1"])
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("sh failed: slurp: selection cancelled"),
            "{error}"
        );
        assert!(matches!(capture(&["true"]), Err(Error::Capture(_))));
        assert!(matches!(
            capture(&["/nonexistent/grimshot"]),
            Err(Error::Capture(_))
        ));
        assert!(matches!(capture::<&str>(&[]), Err(Error::Capture(_))));
    }

    const LONG_URI: &str = "otpauth://totp/Google:codingmyc@gmail.com?secret=JBSWY3DPEHPK3PXP\
                            &issuer=Google&algorithm=SHA1&digits=6&period=30";

    #[test]
    fn png_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qr.png");
        write_png(LONG_URI, &path).unwrap();
        let uri = find_otpauth_uri(decode_file(&path).unwrap()).unwrap();
        assert_eq!(uri.as_str(), LONG_URI);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "PNG mode is {mode:o}");
        }
        // Existing files are never overwritten.
        assert!(write_png(LONG_URI, &path).is_err());
    }

    #[test]
    fn half_block_lines_round_trip() {
        let matrix = QrMatrix::encode_compact(LONG_URI).unwrap();
        let lines = matrix.half_block_lines(2);
        let side = matrix.width() + 4;
        assert_eq!(lines.len(), side.div_ceil(2));
        assert!(lines.iter().all(|line| line.chars().count() == side));

        // Rebuild the modules from the characters and decode them.
        let scale = 6;
        let height = lines.len() * 2;
        let pixels: Vec<Vec<bool>> = lines
            .iter()
            .flat_map(|line| {
                let (top, bottom): (Vec<bool>, Vec<bool>) = line
                    .chars()
                    .map(|c| (matches!(c, '█' | '▀'), matches!(c, '█' | '▄')))
                    .unzip();
                [top, bottom]
            })
            .collect();
        let image = GrayImage::from_fn((side * scale) as u32, (height * scale) as u32, |x, y| {
            let dark = pixels[y as usize / scale][x as usize / scale];
            Luma([if dark { 0 } else { 255 }])
        });
        let found = decode_image(&DynamicImage::ImageLuma8(image));
        assert_eq!(find_otpauth_uri(found).unwrap().as_str(), LONG_URI);
    }

    #[test]
    fn compact_encoding_is_smaller() {
        let compact = QrMatrix::encode_compact(LONG_URI).unwrap().width();
        let medium = QrMatrix::encode(LONG_URI).unwrap().width();
        assert!(compact < medium, "{compact} vs {medium}");
    }

    #[test]
    fn view_runs_the_viewer_with_a_png() {
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("seen.png");
        let copy_arg = copy.to_str().unwrap();
        view(&["cp", "{file}", copy_arg], LONG_URI).unwrap();
        let uri = find_otpauth_uri(decode_file(&copy).unwrap()).unwrap();
        assert_eq!(uri.as_str(), LONG_URI);

        assert!(matches!(view(&["false"], LONG_URI), Err(Error::Viewer(_))));
        assert!(matches!(
            view(&["/nonexistent/chafa"], LONG_URI),
            Err(Error::Viewer(_))
        ));
        assert!(matches!(view::<&str>(&[], LONG_URI), Err(Error::Viewer(_))));
    }

    #[test]
    fn find_uri_rules() {
        let z = |s: &str| Zeroizing::new(s.to_string());
        assert!(find_otpauth_uri(vec![]).is_err());
        assert!(find_otpauth_uri(vec![z("https://example.com")]).is_err());
        assert!(find_otpauth_uri(vec![z("otpauth-migration://offline?data=x")]).is_err());
        assert!(find_otpauth_uri(vec![z(URI), z(URI)]).is_err());
        assert_eq!(
            find_otpauth_uri(vec![z("hello"), z(URI)]).unwrap().as_str(),
            URI
        );
    }
}
