//! `otp tui`: browse entries, see the selected entry's code, copy it.

use std::collections::HashMap;
use std::io::stdout;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use otp_core::store::Backend;
use otp_core::{Entry, Kind};
use ratatui::crossterm::event::{
    self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, KeyboardEnhancementFlags,
    PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::supports_keyboard_enhancement;
use ratatui::layout::{Constraint, Layout, Margin, Position, Rect};
use ratatui::style::{Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Gauge, List, ListState, Padding, Paragraph, Wrap};
use ratatui::{DefaultTerminal, Frame};

use crate::stores::Stores;

/// What to copy for the picked entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Output {
    Code,
    Secret,
    Uri,
}

/// Runs the TUI and returns the entry picked for copying, if any.
pub fn run(
    stores: &mut Stores,
    only: Option<Backend>,
) -> Result<Option<(String, Backend, Output)>> {
    // Listing may ask for the master password, so it happens before the TUI starts.
    let rows = stores.list(only)?;
    if rows.is_empty() {
        bail!("no entries; add one with `otp insert`");
    }
    let mut app = App::new(rows);
    let mut terminal = ratatui::init();
    // Where the terminal supports it (kitty keyboard protocol), Ctrl+I and Ctrl+? are
    // reported as themselves instead of as Tab and Backspace.
    let enhanced = supports_keyboard_enhancement().unwrap_or(false)
        && execute!(
            stdout(),
            PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
        )
        .is_ok();
    let result = event_loop(&mut terminal, &mut app, stores);
    if enhanced {
        let _ = execute!(stdout(), PopKeyboardEnhancementFlags);
    }
    ratatui::restore();
    Ok(result?.map(|(index, output)| {
        let (name, backend) = app.rows[index].clone();
        (name, backend, output)
    }))
}

fn event_loop(
    terminal: &mut DefaultTerminal,
    app: &mut App,
    stores: &mut Stores,
) -> Result<Option<(usize, Output)>> {
    let mut fetch = |name: &str, backend: Backend| -> Result<Entry> {
        let store = stores.get(backend)?.context("store is unavailable")?;
        store.get(name)?.context("entry not found")
    };
    loop {
        app.load_selected(&mut fetch);
        terminal.draw(|frame| app.render(frame, SystemTime::now()))?;
        // Wake up regularly so TOTP codes and countdowns stay current.
        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        // Drain pending input before decrypting anything, so key repeat stays responsive.
        loop {
            if let Event::Key(key) = event::read()? {
                match app.handle_key(key) {
                    Action::None => {}
                    Action::Quit => return Ok(None),
                    Action::Copy(index, output) => return Ok(Some((index, output))),
                }
                // The inspect window acts on the entry: decrypt it before the next key.
                if app.mode == Mode::Inspect {
                    app.load_selected(&mut fetch);
                }
            }
            if !event::poll(Duration::ZERO)? {
                break;
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    None,
    Quit,
    /// Copy something of `rows[index]` and quit.
    Copy(usize, Output),
}

/// Which window has the focus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    List,
    Help,
    Inspect,
}

/// Ctrl+? (kitty protocol), Ctrl+/ (sent as Ctrl+7 by legacy terminals) or F1.
fn is_help_key(key: &KeyEvent) -> bool {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    matches!(key.code, KeyCode::F(1))
        || (ctrl && matches!(key.code, KeyCode::Char('?' | '/' | '7')))
}

/// Ctrl+I (kitty protocol), or Tab, which is what legacy terminals send for Ctrl+I.
fn is_inspect_key(key: &KeyEvent) -> bool {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    key.code == KeyCode::Tab || (ctrl && key.code == KeyCode::Char('i'))
}

pub struct App {
    rows: Vec<(String, Backend)>,
    mode: Mode,
    filter: String,
    /// Indices into `rows` matching the filter.
    visible: Vec<usize>,
    list: ListState,
    /// Decrypted entries (or the error), by index into `rows`.
    loaded: HashMap<usize, Result<Entry, String>>,
}

impl App {
    pub fn new(rows: Vec<(String, Backend)>) -> Self {
        let mut app = App {
            rows,
            mode: Mode::List,
            filter: String::new(),
            visible: Vec::new(),
            list: ListState::default(),
            loaded: HashMap::new(),
        };
        app.refilter();
        app
    }

    /// The selected index into `rows`.
    pub fn selected(&self) -> Option<usize> {
        self.list
            .selected()
            .and_then(|i| self.visible.get(i).copied())
    }

    fn refilter(&mut self) {
        let previous = self.selected();
        let needle = self.filter.to_lowercase();
        self.visible = (0..self.rows.len())
            .filter(|&i| self.rows[i].0.to_lowercase().contains(&needle))
            .collect();
        // Keep the selected entry if it still matches, otherwise select the first match.
        let position = previous
            .and_then(|previous| self.visible.iter().position(|&i| i == previous))
            .or((!self.visible.is_empty()).then_some(0));
        self.list.select(position);
    }

    fn move_selection(&mut self, delta: isize) {
        if let Some(current) = self.list.selected() {
            let last = self.visible.len().saturating_sub(1);
            let next = current.saturating_add_signed(delta).min(last);
            self.list.select(Some(next));
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Action {
        if key.kind != KeyEventKind::Press {
            return Action::None;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && key.code == KeyCode::Char('c') {
            return Action::Quit;
        }
        match self.mode {
            Mode::List => {}
            Mode::Help => {
                if key.code == KeyCode::Esc {
                    self.mode = Mode::List;
                }
                return Action::None;
            }
            Mode::Inspect => {
                return match key.code {
                    KeyCode::Esc => {
                        self.mode = Mode::List;
                        Action::None
                    }
                    KeyCode::Char('s') if !ctrl => self.copy_loaded(Output::Secret),
                    KeyCode::Char('u') if !ctrl => self.copy_loaded(Output::Uri),
                    _ => Action::None,
                };
            }
        }
        if is_help_key(&key) {
            self.mode = Mode::Help;
            return Action::None;
        }
        if is_inspect_key(&key) {
            if self.selected().is_some() {
                self.mode = Mode::Inspect;
            }
            return Action::None;
        }
        match key.code {
            KeyCode::Esc => return Action::Quit,
            KeyCode::Enter => {
                return match self.selected() {
                    Some(index) => Action::Copy(index, Output::Code),
                    None => Action::None,
                };
            }
            KeyCode::Up => self.move_selection(-1),
            KeyCode::Char('p') if ctrl => self.move_selection(-1),
            KeyCode::Down => self.move_selection(1),
            KeyCode::Char('n') if ctrl => self.move_selection(1),
            KeyCode::Backspace => {
                self.filter.pop();
                self.refilter();
            }
            KeyCode::Char('u') if ctrl => {
                self.filter.clear();
                self.refilter();
            }
            KeyCode::Char(c) if !ctrl => {
                self.filter.push(c);
                self.refilter();
            }
            _ => {}
        }
        Action::None
    }

    /// Copies from the selected entry, once it has been decrypted successfully.
    fn copy_loaded(&self, output: Output) -> Action {
        match self.selected() {
            Some(index) if matches!(self.loaded.get(&index), Some(Ok(_))) => {
                Action::Copy(index, output)
            }
            _ => Action::None,
        }
    }

    /// Decrypts the selected entry the first time it is selected.
    pub fn load_selected(&mut self, fetch: &mut dyn FnMut(&str, Backend) -> Result<Entry>) {
        let Some(index) = self.selected() else {
            return;
        };
        if !self.loaded.contains_key(&index) {
            let (name, backend) = &self.rows[index];
            let entry = fetch(name, *backend).map_err(|e| format!("{e:#}"));
            self.loaded.insert(index, entry);
        }
    }

    pub fn render(&mut self, frame: &mut Frame, now: SystemTime) {
        let [main, prompt] =
            Layout::vertical([Constraint::Min(3), Constraint::Length(3)]).areas(frame.area());
        let [entries, code] =
            Layout::horizontal([Constraint::Min(20), Constraint::Length(34)]).areas(main);
        self.render_entries(frame, entries);
        self.render_code(frame, code, now);
        self.render_prompt(frame, prompt);
        match self.mode {
            Mode::List => {}
            Mode::Help => render_help(frame),
            Mode::Inspect => self.render_inspect(frame),
        }
    }

    fn render_entries(&mut self, frame: &mut Frame, area: Rect) {
        let title = format!(" Entries {}/{} ", self.visible.len(), self.rows.len());
        let block = Block::bordered().title(title);
        if self.visible.is_empty() {
            let message = Paragraph::new("No match".dim()).block(block);
            frame.render_widget(message, area);
            return;
        }
        let items = self.visible.iter().map(|&i| self.rows[i].0.as_str());
        let list = List::new(items)
            .block(block)
            .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
            .highlight_symbol("> ");
        frame.render_stateful_widget(list, area, &mut self.list);
    }

    fn render_code(&self, frame: &mut Frame, area: Rect, now: SystemTime) {
        let block = Block::bordered().title(" Code ");
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let Some(index) = self.selected() else {
            return;
        };
        let (_, backend) = &self.rows[index];
        let entry = match self.loaded.get(&index) {
            None => {
                frame.render_widget(Paragraph::new("Decrypting…".dim()), inner);
                return;
            }
            Some(Err(error)) => {
                let error = Paragraph::new(error.as_str().red()).wrap(Wrap { trim: true });
                frame.render_widget(error, inner);
                return;
            }
            Some(Ok(entry)) => entry,
        };

        let [code_area, gauge_area, _, details_area] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .areas(inner);

        match entry.otp.kind {
            Kind::Totp { period } => {
                // Generating a TOTP code does not modify the entry.
                let code = entry.otp.clone().generate(now);
                let remaining = code.valid_for.map_or(0, |d| d.as_secs());
                let line = Line::from(group_digits(&code.value).bold()).centered();
                frame.render_widget(Paragraph::new(vec![Line::default(), line]), code_area);
                let gauge = Gauge::default()
                    .ratio(remaining as f64 / f64::from(period))
                    .label(format!("{remaining}s"))
                    .gauge_style(if remaining <= 5 {
                        Style::new().red()
                    } else {
                        Style::new().green()
                    });
                frame.render_widget(gauge, gauge_area.inner(Margin::new(1, 0)));
            }
            Kind::Hotp { counter } => {
                // HOTP codes consume the counter, so only generate on request.
                let lines = vec![
                    Line::from(format!("HOTP, counter {counter}")).centered(),
                    Line::from("Enter to generate".dim()).centered(),
                ];
                frame.render_widget(Paragraph::new(lines), code_area);
            }
        }

        let field = |label: &'static str, value: String| {
            Line::from(vec![
                Span::from(format!(" {label:<8}")).dim(),
                Span::from(value),
            ])
        };
        let details = vec![
            field(
                "issuer",
                entry.otp.issuer.clone().unwrap_or_else(|| "-".into()),
            ),
            field(
                "account",
                entry.otp.account.clone().unwrap_or_else(|| "-".into()),
            ),
            field("store", backend.to_string()),
        ];
        frame.render_widget(Paragraph::new(details), details_area);
    }

    fn render_prompt(&self, frame: &mut Frame, area: Rect) {
        let help = Line::from(" Enter copy & quit · Tab inspect · Ctrl-/ help · Esc quit ".dim());
        let block = Block::bordered().title(" Filter ").title_bottom(help);
        let inner = block.inner(area);
        frame.render_widget(Paragraph::new(self.filter.as_str()).block(block), area);
        // The cursor is hidden while a window is open.
        if self.mode == Mode::List {
            let cursor = inner.x + self.filter.chars().count() as u16;
            frame.set_cursor_position(Position::new(cursor.min(inner.right()), inner.y));
        }
    }

    fn render_inspect(&self, frame: &mut Frame) {
        let Some(index) = self.selected() else {
            return;
        };
        let (name, backend) = &self.rows[index];
        let area = centered(frame.area(), 76, frame.area().height);
        let block = Block::bordered()
            .padding(Padding::horizontal(1))
            .title(format!(" {name} "))
            .title_bottom(Line::from(" s copy secret · u copy URI · Esc close ".dim()));
        let inner_width = block.inner(area).width.max(1) as usize;

        let lines = match self.loaded.get(&index) {
            None => vec![Line::from("Decrypting…".dim())],
            Some(Err(error)) => vec![Line::from(error.as_str().red())],
            Some(Ok(entry)) => {
                let otp = &entry.otp;
                let field = |label: &'static str, value: String| {
                    Line::from(vec![
                        Span::from(format!("{label:<10} ")).dim(),
                        Span::from(value),
                    ])
                };
                let optional = |value: &Option<String>| value.clone().unwrap_or_else(|| "-".into());
                vec![
                    field("secret", otp.secret_base32()).bold(),
                    field("type", crate::describe_kind(otp.kind)),
                    field("algorithm", otp.algorithm.to_string()),
                    field("digits", otp.digits.to_string()),
                    field("issuer", optional(&otp.issuer)),
                    field("account", optional(&otp.account)),
                    field("store", backend.to_string()),
                    field("created", crate::timestamp(entry.meta.created_at)),
                    field("updated", crate::timestamp(entry.meta.updated_at)),
                    Line::default(),
                    Line::from("otpauth URI".dim()),
                    Line::from(otp.to_uri()),
                ]
            }
        };
        // Size the window to its wrapped content.
        let height: usize = lines
            .iter()
            .map(|line| line.width().div_ceil(inner_width).max(1))
            .sum();
        let area = centered(frame.area(), area.width, height as u16 + 2);
        frame.render_widget(Clear, area);
        let paragraph = Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false });
        frame.render_widget(paragraph, area);
    }
}

const HELP: &[(&str, &str)] = &[
    ("↑ / Ctrl-P", "previous entry"),
    ("↓ / Ctrl-N", "next entry"),
    ("typing", "filter entries (case-insensitive)"),
    ("Backspace", "delete the last filter character"),
    ("Ctrl-U", "clear the filter"),
    ("Enter", "copy the code and quit"),
    ("Tab / Ctrl-I", "inspect the entry: secret and details"),
    ("Ctrl-? / Ctrl-/ / F1", "show this help"),
    ("Esc / Ctrl-C", "quit"),
    ("", ""),
    ("In the inspect window", ""),
    ("s", "copy the base32 secret and quit"),
    ("u", "copy the otpauth:// URI and quit"),
    ("Esc", "close the window"),
];

fn render_help(frame: &mut Frame) {
    let lines: Vec<Line> = HELP
        .iter()
        .map(|&(keys, action)| match (keys, action) {
            (heading, "") => Line::from(heading.bold()),
            _ => Line::from(vec![
                Span::from(format!("  {keys:<22}")).bold(),
                action.into(),
            ]),
        })
        .collect();
    let area = centered(frame.area(), 66, lines.len() as u16 + 2);
    let block = Block::bordered()
        .padding(Padding::horizontal(1))
        .title(" Help ")
        .title_bottom(Line::from(" Esc close ".dim()));
    frame.render_widget(Clear, area);
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// A `width` × `height` rectangle centered in `area`, shrunk to fit.
fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}

/// Splits a code in two halves for readability: `123456` → `123 456`.
fn group_digits(code: &str) -> String {
    let (left, right) = code.split_at(code.len() / 2);
    format!("{left} {right}")
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use otp_core::OtpSecret;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;

    fn app(names: &[&str]) -> App {
        App::new(
            names
                .iter()
                .map(|name| (name.to_string(), Backend::Native))
                .collect(),
        )
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    fn type_text(app: &mut App, text: &str) {
        for c in text.chars() {
            assert_eq!(app.handle_key(key(KeyCode::Char(c))), Action::None);
        }
    }

    fn visible_names(app: &App) -> Vec<&str> {
        app.visible
            .iter()
            .map(|&i| app.rows[i].0.as_str())
            .collect()
    }

    // RFC 6238 SHA1 secret: 94287082 at t=59 with 8 digits.
    fn totp_entry() -> Entry {
        let mut otp =
            OtpSecret::new(b"12345678901234567890".to_vec(), Kind::Totp { period: 30 }).unwrap();
        otp.digits = 8;
        otp.issuer = Some("Google".into());
        otp.account = Some("alice@gmail.com".into());
        Entry::new(otp)
    }

    fn render(app: &mut App, now: SystemTime) -> String {
        render_at(app, now, 70, 12)
    }

    fn render_sized(app: &mut App, width: u16, height: u16) -> String {
        render_at(app, SystemTime::now(), width, height)
    }

    fn render_at(app: &mut App, now: SystemTime, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| app.render(frame, now)).unwrap();
        let buffer = terminal.backend().buffer();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn filter_is_a_case_insensitive_substring() {
        let mut app = app(&["google.com/Alice", "github", "GitLab/x", "other"]);
        assert_eq!(visible_names(&app).len(), 4);
        type_text(&mut app, "GI");
        assert_eq!(visible_names(&app), ["github", "GitLab/x"]);
        type_text(&mut app, "tl");
        assert_eq!(visible_names(&app), ["GitLab/x"]);
        app.handle_key(key(KeyCode::Backspace));
        app.handle_key(key(KeyCode::Backspace));
        assert_eq!(visible_names(&app), ["github", "GitLab/x"]);
        app.handle_key(ctrl('u'));
        assert_eq!(visible_names(&app).len(), 4);
        type_text(&mut app, "alice");
        assert_eq!(visible_names(&app), ["google.com/Alice"]);
    }

    #[test]
    fn selection_moves_and_follows_the_filter() {
        let mut app = app(&["a/one", "b/two", "a/three"]);
        assert_eq!(app.selected(), Some(0));
        app.handle_key(key(KeyCode::Up));
        assert_eq!(app.selected(), Some(0), "stays at the top");
        app.handle_key(key(KeyCode::Down));
        app.handle_key(ctrl('n'));
        app.handle_key(key(KeyCode::Down));
        assert_eq!(app.selected(), Some(2), "stops at the bottom");
        app.handle_key(ctrl('p'));
        assert_eq!(app.selected(), Some(1));

        // The selected entry is kept when it still matches...
        type_text(&mut app, "two");
        assert_eq!(app.selected(), Some(1));
        // ...and the first match is selected otherwise.
        app.handle_key(ctrl('u'));
        type_text(&mut app, "a/");
        assert_eq!(app.selected(), Some(0));
        type_text(&mut app, "zzz");
        assert_eq!(app.selected(), None);
    }

    #[test]
    fn enter_picks_and_escape_quits() {
        let mut app = app(&["a", "b"]);
        app.handle_key(key(KeyCode::Down));
        assert_eq!(
            app.handle_key(key(KeyCode::Enter)),
            Action::Copy(1, Output::Code)
        );
        assert_eq!(app.handle_key(key(KeyCode::Esc)), Action::Quit);
        assert_eq!(app.handle_key(ctrl('c')), Action::Quit);
        type_text(&mut app, "nothing");
        assert_eq!(app.handle_key(key(KeyCode::Enter)), Action::None);
    }

    #[test]
    fn entries_are_fetched_once() {
        let mut app = app(&["a", "b"]);
        let mut calls = Vec::new();
        let mut fetch = |name: &str, _: Backend| -> Result<Entry> {
            calls.push(name.to_string());
            if name == "b" {
                bail!("gpg: decryption failed: No secret key")
            }
            Ok(totp_entry())
        };
        app.load_selected(&mut fetch);
        app.load_selected(&mut fetch);
        app.handle_key(key(KeyCode::Down));
        app.load_selected(&mut fetch);
        app.load_selected(&mut fetch);
        assert_eq!(calls, ["a", "b"]);
        assert!(matches!(app.loaded.get(&1), Some(Err(e)) if e.contains("No secret key")));
    }

    #[test]
    fn renders_the_selected_totp_code() {
        let mut app = app(&["google.com/alice", "github"]);
        app.load_selected(&mut |_, _| Ok(totp_entry()));
        let screen = render(&mut app, UNIX_EPOCH + Duration::from_secs(59));
        assert!(screen.contains("Entries 2/2"), "{screen}");
        assert!(screen.contains("> google.com/alice"), "{screen}");
        assert!(screen.contains("9428 7082"), "{screen}");
        assert!(screen.contains("1s"), "{screen}");
        assert!(screen.contains("issuer  Google"), "{screen}");
        assert!(screen.contains("account alice@gmail.com"), "{screen}");
        assert!(screen.contains("store   native"), "{screen}");
        assert!(screen.contains("Enter copy & quit"), "{screen}");
    }

    #[test]
    fn renders_hotp_errors_and_empty_matches() {
        let mut app = app(&["hotp", "broken"]);
        app.load_selected(&mut |_, _| {
            Ok(Entry::new(
                OtpSecret::new(b"k".to_vec(), Kind::Hotp { counter: 3 }).unwrap(),
            ))
        });
        let screen = render(&mut app, SystemTime::now());
        assert!(screen.contains("HOTP, counter 3"), "{screen}");
        assert!(screen.contains("Enter to generate"), "{screen}");

        app.handle_key(key(KeyCode::Down));
        app.load_selected(&mut |_, _| bail!("gpg failed"));
        assert!(render(&mut app, SystemTime::now()).contains("gpg failed"));

        type_text(&mut app, "zzz");
        let screen = render(&mut app, SystemTime::now());
        assert!(screen.contains("Entries 0/2"), "{screen}");
        assert!(screen.contains("No match"), "{screen}");
        assert!(screen.contains("zzz"), "{screen}");
    }

    fn with(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    #[test]
    fn help_opens_with_every_help_key_and_closes_with_escape() {
        let ctrl_shift = KeyModifiers::CONTROL | KeyModifiers::SHIFT;
        for help in [
            key(KeyCode::F(1)),
            ctrl('/'),
            ctrl('7'), // Ctrl+/ on legacy terminals
            with(KeyCode::Char('?'), ctrl_shift),
            with(KeyCode::Char('/'), ctrl_shift),
        ] {
            let mut app = app(&["a", "b"]);
            assert_eq!(app.handle_key(help), Action::None);
            assert_eq!(app.mode, Mode::Help, "{help:?}");
            // Keys other than Esc are ignored while the help is shown.
            type_text(&mut app, "x");
            assert_eq!(app.handle_key(key(KeyCode::Enter)), Action::None);
            assert_eq!(app.filter, "");
            // Esc closes the help instead of quitting.
            assert_eq!(app.handle_key(key(KeyCode::Esc)), Action::None);
            assert_eq!(app.mode, Mode::List);
        }
        // Ctrl+? shares its byte with Backspace on legacy terminals: that stays a Backspace.
        let mut app = app(&["a"]);
        type_text(&mut app, "ab");
        app.handle_key(key(KeyCode::Backspace));
        assert_eq!((app.mode, app.filter.as_str()), (Mode::List, "a"));
    }

    #[test]
    fn inspect_copies_secret_or_uri() {
        for inspect in [key(KeyCode::Tab), ctrl('i')] {
            let mut app = app(&["a", "b"]);
            app.handle_key(key(KeyCode::Down));
            app.handle_key(inspect);
            assert_eq!(app.mode, Mode::Inspect, "{inspect:?}");
            // Nothing to copy until the entry is decrypted.
            assert_eq!(app.handle_key(key(KeyCode::Char('s'))), Action::None);
            app.load_selected(&mut |_, _| Ok(totp_entry()));
            assert_eq!(
                app.handle_key(key(KeyCode::Char('s'))),
                Action::Copy(1, Output::Secret)
            );
            assert_eq!(
                app.handle_key(key(KeyCode::Char('u'))),
                Action::Copy(1, Output::Uri)
            );
            // Other keys neither filter nor move.
            type_text(&mut app, "x");
            app.handle_key(key(KeyCode::Up));
            assert_eq!((app.filter.as_str(), app.selected()), ("", Some(1)));
            assert_eq!(app.handle_key(key(KeyCode::Esc)), Action::None);
            assert_eq!(app.mode, Mode::List);
            assert_eq!(app.handle_key(ctrl('c')), Action::Quit);
        }

        // Errors cannot be copied, and there is nothing to inspect without a match.
        let mut app = app(&["a"]);
        app.load_selected(&mut |_, _| bail!("gpg failed"));
        app.handle_key(key(KeyCode::Tab));
        assert_eq!(app.handle_key(key(KeyCode::Char('u'))), Action::None);
        app.handle_key(key(KeyCode::Esc));
        type_text(&mut app, "zzz");
        app.handle_key(key(KeyCode::Tab));
        assert_eq!(app.mode, Mode::List);
    }

    #[test]
    fn renders_help_and_inspect_windows() {
        let mut app = app(&["google.com/alice"]);
        app.load_selected(&mut |_, _| Ok(totp_entry()));

        app.handle_key(key(KeyCode::F(1)));
        let screen = render_sized(&mut app, 80, 20);
        assert!(screen.contains(" Help "), "{screen}");
        assert!(screen.contains("Ctrl-? / Ctrl-/ / F1"), "{screen}");
        assert!(
            screen.contains("copy the base32 secret and quit"),
            "{screen}"
        );
        app.handle_key(key(KeyCode::Esc));

        app.handle_key(key(KeyCode::Tab));
        let screen = render_sized(&mut app, 80, 20);
        assert!(screen.contains(" google.com/alice "), "{screen}");
        assert!(
            screen.contains("secret     GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
            "{screen}"
        );
        assert!(screen.contains("type       TOTP, 30s period"), "{screen}");
        assert!(screen.contains("algorithm  SHA1"), "{screen}");
        assert!(screen.contains("digits     8"), "{screen}");
        assert!(screen.contains("store      native"), "{screen}");
        assert!(
            screen.contains("otpauth://totp/Google:alice@gmail.com?secret="),
            "{screen}"
        );
        assert!(
            screen.contains("s copy secret · u copy URI · Esc close"),
            "{screen}"
        );
    }

    #[test]
    fn groups_digits() {
        assert_eq!(group_digits("123456"), "123 456");
        assert_eq!(group_digits("12345678"), "1234 5678");
        assert_eq!(group_digits("1234567"), "123 4567");
    }
}
