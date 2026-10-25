//! A full-screen interface over the same [`Session`] as the REPL.
//!
//! Panes: scan results (left), the address table (right) and a memory view of the
//! selection (bottom). Scans run on a background thread so the UI stays live.

use std::io::{self, BufRead, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use procodile::scan::{Progress, Scan, ScanOptions, ValueType};
use procodile::{Address, Module};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Gauge, List, ListItem, ListState, Paragraph};
use ratatui::{DefaultTerminal, Frame};

use crate::commands::{
    default_tolerance, describe, parse_condition, parse_value, render_struct_at, table_line,
};
use crate::format::{self, Format};
use crate::session::Session;
use crate::table::Entry;

/// Set while the TUI runs, so `:tui` inside it is refused.
pub static ACTIVE: AtomicBool = AtomicBool::new(false);

pub fn run(session: &mut Session) -> Result<(), String> {
    if ACTIVE.swap(true, Ordering::Relaxed) {
        return Err("already in the TUI".into());
    }
    let result = App::new(session).run();
    ACTIVE.store(false, Ordering::Relaxed);
    result.map_err(|e| e.to_string())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    Scan,
    Table,
}

enum Mode {
    Normal,
    Input { kind: InputKind, buffer: String },
    Picker(Picker),
}

#[derive(Clone, Copy)]
enum InputKind {
    FirstScan,
    NextScan,
    WriteEntry(usize),
    Describe(usize),
    StructView,
    Command,
}

impl InputKind {
    fn prompt(self) -> &'static str {
        match self {
            InputKind::FirstScan => "first scan (100 | between 1 10 | unknown | gt 5): ",
            InputKind::NextScan => "next scan (93 | changed | unchanged | inc | dec | dec-by 7): ",
            InputKind::WriteEntry(_) => "new value: ",
            InputKind::Describe(_) => "description: ",
            InputKind::StructView => "view selection as struct (empty for hex): ",
            InputKind::Command => ":",
        }
    }
}

struct Picker {
    filter: String,
    processes: Vec<(u32, String)>,
    state: ListState,
}

impl Picker {
    fn new() -> Self {
        let mut processes: Vec<(u32, String)> = procodile::process::processes()
            .map(|ps| {
                ps.map(|p| (p.pid(), p.name().to_string_lossy().into_owned()))
                    .collect()
            })
            .unwrap_or_default();
        processes.sort_by(|a, b| {
            a.1.to_lowercase()
                .cmp(&b.1.to_lowercase())
                .then(a.0.cmp(&b.0))
        });
        Self {
            filter: String::new(),
            processes,
            state: ListState::default().with_selected(Some(0)),
        }
    }

    fn visible(&self) -> Vec<&(u32, String)> {
        let filter = self.filter.to_lowercase();
        self.processes
            .iter()
            .filter(|(pid, name)| {
                name.to_lowercase().contains(&filter) || pid.to_string().starts_with(&filter)
            })
            .collect()
    }
}

type ScanJob = JoinHandle<(Option<Scan>, Result<Scan, procodile::Error>)>;

struct Job {
    progress: Arc<Progress>,
    thread: ScanJob,
    started: Instant,
    /// The scan being narrowed, handed back if the job fails.
    first: bool,
}

struct App<'s> {
    session: &'s mut Session,
    focus: Focus,
    mode: Mode,
    scan_selected: usize,
    scan_offset: usize,
    table_selected: usize,
    status: String,
    job: Option<Job>,
    modules: Vec<Module>,
    modules_loaded: Option<Instant>,
    pending_command: Option<String>,
    /// Show the selection as this struct instead of hex.
    struct_view: Option<String>,
    struct_depth: usize,
    struct_scroll: usize,
    quit: bool,
}

impl<'s> App<'s> {
    fn new(session: &'s mut Session) -> Self {
        let status = match &session.target {
            Some(_) => {
                "Tab: switch pane  f/n: scan  p: process  : command  ?: help  q: quit".into()
            }
            None => "press p to pick a process to attach to".into(),
        };
        Self {
            session,
            focus: Focus::Scan,
            mode: Mode::Normal,
            scan_selected: 0,
            scan_offset: 0,
            table_selected: 0,
            status,
            job: None,
            modules: Vec::new(),
            modules_loaded: None,
            pending_command: None,
            struct_view: None,
            struct_depth: 1,
            struct_scroll: 0,
            quit: false,
        }
    }

    fn run(&mut self) -> io::Result<()> {
        let mut terminal = ratatui::try_init()?;
        let result = self.event_loop(&mut terminal);
        ratatui::restore();
        result
    }

    fn event_loop(&mut self, terminal: &mut DefaultTerminal) -> io::Result<()> {
        while !self.quit {
            self.poll_job();
            self.refresh_modules();
            terminal.draw(|f| self.draw(f))?;
            if event::poll(Duration::from_millis(100))?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                self.on_key(key);
            }
            if let Some(line) = self.pending_command.take() {
                ratatui::restore();
                let keep_going = crate::execute(self.session, &line);
                if keep_going {
                    print!("\n[press Enter to return to the TUI]");
                    io::stdout().flush()?;
                    io::stdin().lock().read_line(&mut String::new())?;
                }
                *terminal = ratatui::try_init()?;
                self.quit |= !keep_going;
                self.clamp_selection();
            }
        }
        Ok(())
    }

    // --- background scans -------------------------------------------------------------

    fn start_scan(&mut self, condition: &str, first: bool) {
        if self.job.is_some() {
            return self.set_status("a scan is already running");
        }
        let handle = match self.session.target() {
            Ok(t) => t.handle.clone(),
            Err(e) => return self.set_status(e),
        };
        let words: Vec<String> = condition.split_whitespace().map(String::from).collect();
        if words.is_empty() {
            return;
        }
        let ty = match (&self.session.scan, first) {
            (Some(scan), false) => scan.value_type(),
            (None, false) => return self.set_status("no scan to narrow; press f to start one"),
            _ => self.session.default_type,
        };
        let compare = match parse_condition(&words, ty, first) {
            Ok(c) => c,
            Err(e) => return self.set_status(e),
        };

        let progress = Arc::new(Progress::new());
        let thread = if first {
            self.session.scan = None;
            let options = ScanOptions {
                float_tolerance: default_tolerance(ty, &words),
                ..ScanOptions::new(ty)
            };
            let progress = progress.clone();
            thread::spawn(move || {
                (
                    None,
                    Scan::first(&handle, options, compare, Some(&progress)),
                )
            })
        } else {
            let mut scan = self.session.scan.take().unwrap();
            let progress = progress.clone();
            thread::spawn(move || match scan.next(&handle, compare, Some(&progress)) {
                Ok(()) => (None, Ok(scan)),
                Err(e) => (Some(scan), Err(e)),
            })
        };
        self.job = Some(Job {
            progress,
            thread,
            started: Instant::now(),
            first,
        });
        self.scan_selected = 0;
        self.scan_offset = 0;
    }

    fn poll_job(&mut self) {
        if !self.job.as_ref().is_some_and(|j| j.thread.is_finished()) {
            return;
        }
        let job = self.job.take().unwrap();
        let elapsed = job.started.elapsed().as_secs_f64();
        let (previous, result) = job.thread.join().expect("scan thread panicked");
        match result {
            Ok(scan) => {
                self.status = format!("{} results ({elapsed:.2}s)", scan.len());
                self.session.scan = Some(scan);
            }
            Err(e) => {
                self.session.scan = previous;
                self.status = match e {
                    procodile::Error::Cancelled if job.first => "scan cancelled".into(),
                    procodile::Error::Cancelled => "scan cancelled; previous results kept".into(),
                    e => format!("error: {e}"),
                };
            }
        }
    }

    fn refresh_modules(&mut self) {
        let stale = self
            .modules_loaded
            .is_none_or(|t| t.elapsed() > Duration::from_secs(2));
        if stale {
            self.modules = self
                .session
                .handle()
                .ok()
                .and_then(|h| h.modules().ok())
                .unwrap_or_default();
            self.modules_loaded = Some(Instant::now());
        }
    }

    // --- input ------------------------------------------------------------------------

    fn set_status(&mut self, status: impl Into<String>) {
        self.status = status.into();
    }

    fn on_key(&mut self, key: KeyEvent) {
        let ctrl_c =
            key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c');
        if ctrl_c && let Some(job) = &self.job {
            job.progress.cancel();
            return;
        }
        match std::mem::replace(&mut self.mode, Mode::Normal) {
            Mode::Normal => self.on_normal_key(key, ctrl_c),
            Mode::Input { kind, mut buffer } => match key.code {
                KeyCode::Esc => {}
                KeyCode::Enter => self.submit(kind, buffer),
                KeyCode::Backspace => {
                    buffer.pop();
                    self.mode = Mode::Input { kind, buffer };
                }
                KeyCode::Char(_) if ctrl_c => {}
                KeyCode::Char(c) => {
                    buffer.push(c);
                    self.mode = Mode::Input { kind, buffer };
                }
                _ => self.mode = Mode::Input { kind, buffer },
            },
            Mode::Picker(mut picker) => {
                let count = picker.visible().len();
                let selected = picker.state.selected().unwrap_or(0);
                match key.code {
                    KeyCode::Esc => return,
                    KeyCode::Char(_) if ctrl_c => return,
                    KeyCode::Enter => {
                        if let Some(&&(pid, _)) = picker.visible().get(selected) {
                            match self.session.attach(pid) {
                                Ok(t) => {
                                    self.status = format!("Process {} ({}) attached", t.pid, t.name)
                                }
                                Err(e) => self.status = format!("error: {e}"),
                            }
                            self.modules_loaded = None;
                            self.clamp_selection();
                        }
                        return;
                    }
                    KeyCode::Up => picker.state.select(Some(selected.saturating_sub(1))),
                    KeyCode::Down => picker
                        .state
                        .select(Some((selected + 1).min(count.saturating_sub(1)))),
                    KeyCode::Backspace => {
                        picker.filter.pop();
                        picker.state.select(Some(0));
                    }
                    KeyCode::Char(c) => {
                        picker.filter.push(c);
                        picker.state.select(Some(0));
                    }
                    _ => {}
                }
                self.mode = Mode::Picker(picker);
            }
        }
    }

    fn on_normal_key(&mut self, key: KeyEvent, ctrl_c: bool) {
        let input = |kind| Mode::Input {
            kind,
            buffer: String::new(),
        };
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            _ if ctrl_c => self.quit = true,
            KeyCode::Tab | KeyCode::BackTab => {
                self.focus = match self.focus {
                    Focus::Scan => Focus::Table,
                    Focus::Table => Focus::Scan,
                }
            }
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::PageUp => self.move_selection(-20),
            KeyCode::PageDown => self.move_selection(20),
            KeyCode::Home | KeyCode::Char('g') => self.move_selection(isize::MIN / 2),
            KeyCode::End | KeyCode::Char('G') => self.move_selection(isize::MAX / 2),
            KeyCode::Char('p') => self.mode = Mode::Picker(Picker::new()),
            KeyCode::Char(':') => self.mode = input(InputKind::Command),
            KeyCode::Char('?') => {
                self.status = "f first scan  n next scan  r reset  t type  a add to table  \
                    space freeze  e edit  D describe  d delete  v struct view  p process  \
                    : command"
                    .into()
            }
            KeyCode::Char('f') => self.mode = input(InputKind::FirstScan),
            KeyCode::Char('v') => {
                if self.session.structs.is_empty() {
                    self.status = "no structs defined; use :struct define or :struct load".into();
                } else {
                    self.mode = input(InputKind::StructView);
                }
            }
            KeyCode::Char('+') if self.struct_view.is_some() => self.struct_depth += 1,
            KeyCode::Char('-') if self.struct_view.is_some() => {
                self.struct_depth = self.struct_depth.saturating_sub(1)
            }
            KeyCode::Char(']') if self.struct_view.is_some() => self.struct_scroll += 1,
            KeyCode::Char('[') if self.struct_view.is_some() => {
                self.struct_scroll = self.struct_scroll.saturating_sub(1)
            }
            KeyCode::Char('n') if self.session.scan.is_some() => {
                self.mode = input(InputKind::NextScan)
            }
            KeyCode::Char('r') if self.job.is_none() => {
                self.session.scan = None;
                self.status = "scan discarded".into();
            }
            KeyCode::Char('t') if self.session.scan.is_none() && self.job.is_none() => {
                let all = ValueType::ALL;
                let i = all
                    .iter()
                    .position(|&t| t == self.session.default_type)
                    .unwrap_or(0);
                self.session.default_type = all[(i + 1) % all.len()];
            }
            KeyCode::Char('a') | KeyCode::Enter if self.focus == Focus::Scan => self.add_selected(),
            KeyCode::Char(' ') if self.focus == Focus::Table => self.toggle_freeze(),
            KeyCode::Char('e') | KeyCode::Enter if self.focus == Focus::Table => {
                if self.table_selected < self.session.table.entries.len() {
                    self.mode = input(InputKind::WriteEntry(self.table_selected));
                }
            }
            KeyCode::Char('D') if self.focus == Focus::Table => {
                if self.table_selected < self.session.table.entries.len() {
                    self.mode = input(InputKind::Describe(self.table_selected));
                }
            }
            KeyCode::Char('d') | KeyCode::Delete
                if self.focus == Focus::Table
                    && self.table_selected < self.session.table.entries.len() =>
            {
                let _ = self.session.remove_entry(self.table_selected);
                self.clamp_selection();
            }
            _ => {}
        }
    }

    fn submit(&mut self, kind: InputKind, buffer: String) {
        match kind {
            InputKind::FirstScan => self.start_scan(&buffer, true),
            InputKind::NextScan => self.start_scan(&buffer, false),
            InputKind::Command => {
                if !buffer.trim().is_empty() {
                    self.pending_command = Some(buffer);
                }
            }
            InputKind::StructView => {
                let name = buffer.trim();
                self.struct_scroll = 0;
                if name.is_empty() {
                    self.struct_view = None;
                } else if self.session.structs.get(name).is_some() {
                    self.struct_view = Some(name.to_owned());
                } else {
                    let names: Vec<&str> = self
                        .session
                        .structs
                        .iter()
                        .map(|d| d.name.as_str())
                        .collect();
                    self.status = format!("no struct '{name}' (have: {})", names.join(", "));
                }
            }
            InputKind::Describe(i) => {
                if let Ok(entry) = self.session.table.get_mut(i) {
                    entry.description = buffer;
                }
            }
            InputKind::WriteEntry(i) => {
                let result = (|| {
                    let entry = self.session.table.get(i)?;
                    let value = parse_value(entry.value_type, &buffer)?;
                    let address = self.session.eval(&entry.address)?;
                    if entry.frozen.is_some() {
                        self.session.freeze(i, Some(value))?;
                    }
                    self.session.write_value(address, value)
                })();
                if let Err(e) = result {
                    self.status = format!("error: {e}");
                }
            }
        }
    }

    fn add_selected(&mut self) {
        let Some(scan) = &self.session.scan else {
            return;
        };
        let Some(m) = scan.results().nth(self.scan_selected) else {
            return;
        };
        self.session.table.entries.push(Entry {
            description: String::new(),
            address: format!("{:#x}", m.address.get()),
            value_type: scan.value_type(),
            frozen: None,
        });
        self.status = format!("added ${}", self.session.table.entries.len() - 1);
    }

    fn toggle_freeze(&mut self) {
        let i = self.table_selected;
        let Ok(entry) = self.session.table.get(i) else {
            return;
        };
        let result = if entry.frozen.is_some() {
            self.session.unfreeze(i).map(|_| format!("${i} unfrozen"))
        } else {
            self.session
                .freeze(i, None)
                .map(|v| format!("${i} frozen at {v}"))
        };
        self.status = result.unwrap_or_else(|e| format!("error: {e}"));
    }

    fn move_selection(&mut self, delta: isize) {
        let (selected, len) = match self.focus {
            Focus::Scan => (
                &mut self.scan_selected,
                self.session.scan.as_ref().map_or(0, Scan::len),
            ),
            Focus::Table => (&mut self.table_selected, self.session.table.entries.len()),
        };
        *selected = selected
            .saturating_add_signed(delta)
            .min(len.saturating_sub(1));
    }

    fn clamp_selection(&mut self) {
        let scan_len = self.session.scan.as_ref().map_or(0, Scan::len);
        self.scan_selected = self.scan_selected.min(scan_len.saturating_sub(1));
        let table_len = self.session.table.entries.len();
        self.table_selected = self.table_selected.min(table_len.saturating_sub(1));
    }

    fn selected_address(&self) -> Option<Address> {
        match self.focus {
            Focus::Scan => self
                .session
                .scan
                .as_ref()?
                .results()
                .nth(self.scan_selected)
                .map(|m| m.address),
            Focus::Table => self
                .session
                .read_entry(self.table_selected)
                .ok()
                .map(|(a, _)| a),
        }
    }

    // --- drawing ----------------------------------------------------------------------

    fn draw(&mut self, f: &mut Frame) {
        let [top, body, memory, bottom] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(6),
            Constraint::Length(if self.struct_view.is_some() { 18 } else { 10 }),
            Constraint::Length(1),
        ])
        .areas(f.area());
        let [left, right] =
            Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)])
                .areas(body);

        self.draw_title(f, top);
        self.draw_scan(f, left);
        self.draw_table(f, right);
        self.draw_memory(f, memory);
        self.draw_status(f, bottom);
        if let Mode::Picker(picker) = &mut self.mode {
            draw_picker(f, picker);
        }
    }

    fn draw_title(&self, f: &mut Frame, area: Rect) {
        let target = match &self.session.target {
            Some(t) => format!("pid {} ({}), {}-bit", t.pid, t.name, t.pointer_width * 8),
            None => "no process".into(),
        };
        let line = Line::from(vec![
            Span::from(" procodile ").bold().reversed(),
            Span::raw(format!("  {target}")),
        ]);
        f.render_widget(Paragraph::new(line), area);
    }

    fn pane_block(&self, title: String, focus: Focus) -> Block<'static> {
        let style = if self.focus == focus {
            Style::new().fg(Color::Cyan)
        } else {
            Style::new().fg(Color::DarkGray)
        };
        Block::bordered().title(title).border_style(style)
    }

    fn draw_scan(&mut self, f: &mut Frame, area: Rect) {
        let ty = self
            .session
            .scan
            .as_ref()
            .map_or(self.session.default_type, Scan::value_type);
        let title = match &self.session.scan {
            Some(scan) if scan.is_snapshot() => format!(" Scan {ty}: {} candidates ", scan.len()),
            Some(scan) => format!(" Scan {ty}: {} results ", scan.len()),
            None => format!(" Scan {ty} (t: change type, f: first scan) "),
        };
        let block = self.pane_block(title, Focus::Scan);
        let inner = block.inner(area);
        f.render_widget(block, area);

        if let Some(job) = &self.job {
            let [_, gauge, _] = Layout::vertical([
                Constraint::Fill(1),
                Constraint::Length(1),
                Constraint::Fill(1),
            ])
            .areas(inner);
            let label = format!(
                "{:.0}% of {}  (Ctrl-C to cancel)",
                job.progress.fraction() * 100.0,
                format::bytes(job.progress.total())
            );
            f.render_widget(
                Gauge::default()
                    .ratio(job.progress.fraction().clamp(0.0, 1.0))
                    .label(label)
                    .gauge_style(Style::new().fg(Color::Cyan)),
                gauge,
            );
            return;
        }
        let Some(scan) = &self.session.scan else {
            return;
        };

        let rows = inner.height as usize;
        if self.scan_selected < self.scan_offset {
            self.scan_offset = self.scan_selected;
        } else if rows > 0 && self.scan_selected >= self.scan_offset + rows {
            self.scan_offset = self.scan_selected + 1 - rows;
        }
        let items: Vec<ListItem> = scan
            .results()
            .enumerate()
            .skip(self.scan_offset)
            .take(rows)
            .map(|(i, m)| {
                let current = self
                    .session
                    .read_value(m.address, ty)
                    .map_or("??".into(), |v| v.to_string());
                let changed = current != m.value.to_string();
                let line = Line::from(vec![
                    Span::raw(format!("#{i:<5}{} ", m.address)),
                    Span::raw(format!("{:<22} ", describe(&self.modules, m.address))).dim(),
                    Span::raw(format!("{:<12} ", m.value)),
                    if changed {
                        Span::raw(current).red()
                    } else {
                        Span::raw(current)
                    },
                ]);
                let item = ListItem::new(line);
                if i == self.scan_selected && self.focus == Focus::Scan {
                    item.style(Style::new().add_modifier(Modifier::REVERSED))
                } else {
                    item
                }
            })
            .collect();
        f.render_widget(List::new(items), inner);
    }

    fn draw_table(&self, f: &mut Frame, area: Rect) {
        let title = format!(" Address table: {} ", self.session.table.entries.len());
        let block = self.pane_block(title, Focus::Table);
        let inner = block.inner(area);
        f.render_widget(block, area);
        if self.session.table.entries.is_empty() {
            f.render_widget(
                Paragraph::new("a: add the selected scan result").dim(),
                inner,
            );
            return;
        }
        let rows = inner.height as usize;
        let offset = (self.table_selected + 1).saturating_sub(rows);
        let items: Vec<ListItem> = (offset..self.session.table.entries.len())
            .take(rows)
            .map(|i| {
                let mut item = ListItem::new(table_line(self.session, i));
                if self.session.table.entries[i].frozen.is_some() {
                    item = item.style(Style::new().fg(Color::Cyan));
                }
                if i == self.table_selected && self.focus == Focus::Table {
                    item = item.add_modifier(Modifier::REVERSED);
                }
                item
            })
            .collect();
        f.render_widget(List::new(items), inner);
    }

    fn draw_memory(&self, f: &mut Frame, area: Rect) {
        let Some(address) = self.selected_address() else {
            f.render_widget(Block::bordered().title(" Memory ").dim(), area);
            return;
        };
        if let Some(name) = &self.struct_view {
            let lines = match render_struct_at(self.session, name, address, self.struct_depth, true)
            {
                Ok(lines) => lines,
                Err(e) => vec![format!("error: {e}")],
            };
            let title = format!(
                " {name} at {address:?} {}  depth {} (+/-)  scroll [ ]  v: change ",
                describe(&self.modules, address),
                self.struct_depth
            );
            let lines: Vec<Line> = lines
                .into_iter()
                .skip(self.struct_scroll)
                .map(Line::from)
                .collect();
            f.render_widget(
                Paragraph::new(lines).block(Block::bordered().title(title)),
                area,
            );
            return;
        }
        let base = address.align_down(16);
        let rows = area.height.saturating_sub(2) as usize;
        let mut buf = vec![0; rows * 16];
        let read = self
            .session
            .handle()
            .ok()
            .and_then(|h| h.read_bytes(base, &mut buf).ok())
            .unwrap_or(0);
        let lines: Vec<Line> = format::memory(base, &buf[..read], Format::Bytes, 1)
            .into_iter()
            .map(Line::from)
            .collect();
        let title = format!(
            " Memory at {address:?} {} ",
            describe(&self.modules, address)
        );
        f.render_widget(
            Paragraph::new(lines).block(Block::bordered().title(title)),
            area,
        );
    }

    fn draw_status(&self, f: &mut Frame, area: Rect) {
        let line = match &self.mode {
            Mode::Input { kind, buffer } => {
                f.set_cursor_position((
                    area.x + (kind.prompt().len() + buffer.chars().count()) as u16,
                    area.y,
                ));
                Line::from(vec![
                    Span::raw(kind.prompt()).bold(),
                    Span::raw(buffer.as_str()),
                ])
            }
            _ => Line::from(self.status.as_str()),
        };
        f.render_widget(Paragraph::new(line), area);
    }
}

fn draw_picker(f: &mut Frame, picker: &mut Picker) {
    let area = f.area();
    let popup = Rect {
        x: area.width / 6,
        y: area.height / 8,
        width: area.width * 2 / 3,
        height: area.height * 3 / 4,
    };
    f.render_widget(Clear, popup);
    let items: Vec<ListItem> = picker
        .visible()
        .iter()
        .map(|(pid, name)| ListItem::new(format!("{pid:>8}  {name}")))
        .collect();
    let title = format!(" Attach to process: {}_ ", picker.filter);
    let list = List::new(items)
        .block(
            Block::bordered()
                .title(title)
                .border_style(Style::new().fg(Color::Cyan)),
        )
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(list, popup, &mut picker.state);
}
