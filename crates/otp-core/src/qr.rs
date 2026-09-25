//! QR code decoding from images and screenshots.

use std::io::ErrorKind;
use std::path::Path;
use std::process::Command;

use image::DynamicImage;
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
        cmd.arg(&file);
    }

    let status = cmd.status().map_err(|e| {
        if e.kind() == ErrorKind::NotFound {
            Error::Capture(format!("{program} not found"))
        } else {
            Error::Io(e)
        }
    })?;
    if !status.success() {
        return Err(Error::Capture(format!("{program} failed ({status})")));
    }
    match std::fs::metadata(&file) {
        Ok(meta) if meta.len() > 0 => decode_file(&file),
        _ => Err(Error::Capture(
            "no screenshot was taken (selection cancelled?)".into(),
        )),
    }
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
        assert!(matches!(capture(&["true"]), Err(Error::Capture(_))));
        assert!(matches!(
            capture(&["/nonexistent/grimshot"]),
            Err(Error::Capture(_))
        ));
        assert!(matches!(capture::<&str>(&[]), Err(Error::Capture(_))));
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
