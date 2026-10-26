//! The pointer scan options popup.

use procodile::scan::PointerScanOptions;
use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph};

use super::help::popup;
use crate::expr::parse_usize;

const TARGET: usize = 0;
const DEPTH: usize = 1;
const OFFSET: usize = 2;
const COUNT: usize = 3;
const MAP: usize = 4;
const READ_ONLY: usize = 5;
const FIELDS: usize = 6;

const LABELS: [&str; FIELDS] = [
    "Target address",
    "Max depth",
    "Max offset",
    "Max results",
    "Saved map id",
    "Scan read-only memory",
];

const HINTS: [&str; FIELDS] = [
    "an address expression: 0x..., #0, $1",
    "pointer dereferences per path",
    "largest offset after each dereference",
    "stop after this many paths",
    "blank: scan the attached process; or a map from `pointer open`",
    "also look for pointers in read-only data (Space toggles)",
];

pub struct PointerForm {
    text: [String; READ_ONLY],
    read_only: bool,
    selected: usize,
    pub error: Option<String>,
}

/// What the form produced when submitted.
pub struct PointerRequest {
    pub target: String,
    pub map: Option<i64>,
    pub read_only: bool,
    pub options: PointerScanOptions,
}

pub enum FormAction {
    None,
    Submit(PointerRequest),
    Cancel,
}

impl PointerForm {
    pub fn new(target: String) -> Self {
        let defaults = PointerScanOptions::default();
        Self {
            text: [
                target,
                defaults.max_depth.to_string(),
                format!("{:#x}", defaults.max_offset),
                defaults.max_results.to_string(),
                String::new(),
            ],
            read_only: false,
            selected: TARGET,
            error: None,
        }
    }

    pub fn on_key(&mut self, key: KeyEvent) -> FormAction {
        match key.code {
            KeyCode::Esc => return FormAction::Cancel,
            KeyCode::Enter => match self.request() {
                Ok(request) => return FormAction::Submit(request),
                Err(e) => self.error = Some(e),
            },
            KeyCode::Up | KeyCode::BackTab => {
                self.selected = (self.selected + FIELDS - 1) % FIELDS;
            }
            KeyCode::Down | KeyCode::Tab => self.selected = (self.selected + 1) % FIELDS,
            KeyCode::Char(' ') if self.selected == READ_ONLY => self.read_only = !self.read_only,
            KeyCode::Char('u')
                if key.modifiers.contains(KeyModifiers::CONTROL) && self.selected < READ_ONLY =>
            {
                self.text[self.selected].clear();
            }
            KeyCode::Char(c) if self.selected < READ_ONLY => self.text[self.selected].push(c),
            KeyCode::Backspace if self.selected < READ_ONLY => {
                self.text[self.selected].pop();
            }
            _ => {}
        }
        FormAction::None
    }

    fn request(&self) -> Result<PointerRequest, String> {
        let number =
            |i: usize| parse_usize(self.text[i].trim()).map_err(|e| format!("{}: {e}", LABELS[i]));
        let options = PointerScanOptions {
            max_depth: number(DEPTH)?,
            max_offset: number(OFFSET)?,
            max_results: number(COUNT)?,
        };
        if options.max_depth == 0 {
            return Err("Max depth must be at least 1".into());
        }
        let map = match self.text[MAP].trim() {
            "" => None,
            id => Some(id.parse().map_err(|_| format!("invalid map id '{id}'"))?),
        };
        let target = self.text[TARGET].trim().to_owned();
        if target.is_empty() && map.is_none() {
            return Err("Target address is required (or a saved map, to use its target)".into());
        }
        Ok(PointerRequest {
            target,
            map,
            read_only: self.read_only,
            options,
        })
    }

    pub fn draw(&self, f: &mut Frame) {
        let mut lines = vec![Line::raw("")];
        for (i, label) in LABELS.iter().enumerate() {
            let selected = i == self.selected;
            let value = if i == READ_ONLY {
                if self.read_only { "[x]" } else { "[ ]" }.to_owned()
            } else if selected {
                format!("{}_", self.text[i])
            } else {
                self.text[i].clone()
            };
            let label = Span::raw(format!("  {label:<24}"));
            let value_style = if selected {
                Style::new().add_modifier(Modifier::REVERSED)
            } else {
                Style::new()
            };
            lines.push(Line::from(vec![
                if selected { label.bold() } else { label },
                Span::styled(format!(" {value:<28} "), value_style),
            ]));
        }
        lines.push(Line::raw(""));
        lines.push(Line::from(format!("  {}", HINTS[self.selected])).dim());
        lines.push(Line::raw(""));
        match &self.error {
            Some(e) => lines.push(Line::from(format!("  {e}")).red()),
            None => lines.push(
                Line::from("  Enter: scan  ↑↓/Tab: move  Ctrl-U: clear field  Esc: cancel")
                    .fg(Color::DarkGray),
            ),
        }

        let area = popup(f.area(), 72, lines.len() as u16 + 2);
        f.render_widget(Clear, area);
        f.render_widget(
            Paragraph::new(lines).block(
                Block::bordered()
                    .title(" Pointer scan ")
                    .border_style(Style::new().fg(Color::Cyan)),
            ),
            area,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_submits() {
        let mut form = PointerForm::new("#0".into());
        form.selected = DEPTH;
        form.on_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        form.on_key(KeyEvent::from(KeyCode::Char('3')));
        form.selected = READ_ONLY;
        form.on_key(KeyEvent::from(KeyCode::Char(' ')));
        let FormAction::Submit(request) = form.on_key(KeyEvent::from(KeyCode::Enter)) else {
            panic!("{:?}", form.error)
        };
        assert_eq!(request.target, "#0");
        assert_eq!(request.options.max_depth, 3);
        assert_eq!(request.options.max_offset, 0x1000);
        assert!(request.read_only);
        assert_eq!(request.map, None);

        form.selected = DEPTH;
        form.on_key(KeyEvent::from(KeyCode::Char('x')));
        assert!(matches!(
            form.on_key(KeyEvent::from(KeyCode::Enter)),
            FormAction::None
        ));
        assert!(form.error.is_some());
    }
}
