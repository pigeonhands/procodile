//! A small multi-line text editor, for writing struct definitions in a popup.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

pub struct Editor {
    lines: Vec<String>,
    /// Cursor position: line index and character (not byte) index within the line.
    row: usize,
    col: usize,
    /// First visible line.
    pub scroll: usize,
}

pub enum EditorAction {
    None,
    Save,
    Cancel,
}

impl Editor {
    pub fn new(text: &str) -> Self {
        let mut lines: Vec<String> = text.lines().map(String::from).collect();
        if lines.is_empty() {
            lines.push(String::new());
        }
        Self {
            lines,
            row: 0,
            col: 0,
            scroll: 0,
        }
    }

    pub fn text(&self) -> String {
        let mut text = self.lines.join("\n");
        text.push('\n');
        text
    }

    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    pub fn cursor(&self) -> (usize, usize) {
        (self.row, self.col)
    }

    /// Moves the cursor to the start of a 1-based line, e.g. to show a parse error.
    pub fn go_to_line(&mut self, line: usize) {
        self.row = line.saturating_sub(1).min(self.lines.len() - 1);
        self.col = 0;
    }

    /// Keeps the cursor within `height` visible lines.
    pub fn scroll_to_cursor(&mut self, height: usize) {
        if self.row < self.scroll {
            self.scroll = self.row;
        } else if height > 0 && self.row >= self.scroll + height {
            self.scroll = self.row + 1 - height;
        }
    }

    fn line_len(&self, row: usize) -> usize {
        self.lines[row].chars().count()
    }

    fn byte_index(&self, row: usize, col: usize) -> usize {
        let line = &self.lines[row];
        line.char_indices().nth(col).map_or(line.len(), |(i, _)| i)
    }

    pub fn on_key(&mut self, key: KeyEvent) -> EditorAction {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('s') if ctrl => return EditorAction::Save,
            KeyCode::Esc => return EditorAction::Cancel,
            KeyCode::Char(_) if ctrl => {}
            KeyCode::Char(c) => self.insert(c),
            KeyCode::Tab => {
                for _ in 0..4 {
                    self.insert(' ');
                }
            }
            KeyCode::Enter => self.newline(),
            KeyCode::Backspace => self.backspace(),
            KeyCode::Delete => self.delete(),
            KeyCode::Left if self.col > 0 => self.col -= 1,
            KeyCode::Left if self.row > 0 => {
                self.row -= 1;
                self.col = self.line_len(self.row);
            }
            KeyCode::Right if self.col < self.line_len(self.row) => self.col += 1,
            KeyCode::Right if self.row + 1 < self.lines.len() => {
                self.row += 1;
                self.col = 0;
            }
            KeyCode::Up if self.row > 0 => {
                self.row -= 1;
                self.col = self.col.min(self.line_len(self.row));
            }
            KeyCode::Down if self.row + 1 < self.lines.len() => {
                self.row += 1;
                self.col = self.col.min(self.line_len(self.row));
            }
            KeyCode::PageUp => {
                self.row = self.row.saturating_sub(10);
                self.col = self.col.min(self.line_len(self.row));
            }
            KeyCode::PageDown => {
                self.row = (self.row + 10).min(self.lines.len() - 1);
                self.col = self.col.min(self.line_len(self.row));
            }
            KeyCode::Home => self.col = 0,
            KeyCode::End => self.col = self.line_len(self.row),
            _ => {}
        }
        EditorAction::None
    }

    fn insert(&mut self, c: char) {
        // A closing brace on an otherwise blank line closes a level of indentation.
        if c == '}'
            && self.col >= 4
            && self.lines[self.row]
                .chars()
                .take(self.col)
                .all(|c| c == ' ')
        {
            self.lines[self.row].drain(..4);
            self.col -= 4;
        }
        let i = self.byte_index(self.row, self.col);
        self.lines[self.row].insert(i, c);
        self.col += 1;
    }

    /// Splits the line at the cursor, carrying the indentation over (plus one level after
    /// an opening brace).
    fn newline(&mut self) {
        let i = self.byte_index(self.row, self.col);
        let rest = self.lines[self.row].split_off(i);
        let line = &self.lines[self.row];
        let mut indent: String = line.chars().take_while(|c| *c == ' ').collect();
        if line.trim_end().ends_with('{') {
            indent.push_str("    ");
        }
        let rest = if rest.trim_start().starts_with('}') {
            indent.truncate(indent.len().saturating_sub(4));
            rest.trim_start().to_owned()
        } else {
            rest
        };
        self.col = indent.chars().count();
        self.row += 1;
        self.lines.insert(self.row, indent + &rest);
    }

    fn backspace(&mut self) {
        if self.col > 0 {
            self.col -= 1;
            let i = self.byte_index(self.row, self.col);
            self.lines[self.row].remove(i);
        } else if self.row > 0 {
            let line = self.lines.remove(self.row);
            self.row -= 1;
            self.col = self.line_len(self.row);
            self.lines[self.row].push_str(&line);
        }
    }

    fn delete(&mut self) {
        if self.col < self.line_len(self.row) {
            let i = self.byte_index(self.row, self.col);
            self.lines[self.row].remove(i);
        } else if self.row + 1 < self.lines.len() {
            let next = self.lines.remove(self.row + 1);
            self.lines[self.row].push_str(&next);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(e: &mut Editor, code: KeyCode) {
        e.on_key(KeyEvent::from(code));
    }

    fn typ(e: &mut Editor, s: &str) {
        for c in s.chars() {
            match c {
                '\n' => press(e, KeyCode::Enter),
                c => press(e, KeyCode::Char(c)),
            }
        }
    }

    #[test]
    fn typing_with_auto_indent() {
        let mut e = Editor::new("");
        typ(&mut e, "struct A {\nhp: i32,\n}");
        assert_eq!(e.text(), "struct A {\n    hp: i32,\n}\n");
    }

    #[test]
    fn editing() {
        let mut e = Editor::new("ab\ncd");
        press(&mut e, KeyCode::End);
        press(&mut e, KeyCode::Delete); // joins the lines
        assert_eq!(e.lines(), ["abcd"]);
        press(&mut e, KeyCode::Backspace);
        press(&mut e, KeyCode::Home);
        typ(&mut e, "é");
        assert_eq!(e.lines(), ["éacd"]);
        assert_eq!(e.cursor(), (0, 1));
        press(&mut e, KeyCode::Enter);
        press(&mut e, KeyCode::Backspace);
        assert_eq!(e.lines(), ["éacd"]);

        e.go_to_line(5);
        assert_eq!(e.cursor(), (0, 0));
        assert!(matches!(
            e.on_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL)),
            EditorAction::Save
        ));
    }
}
