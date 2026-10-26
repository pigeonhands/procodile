//! The key binding reference shown by `?`.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph};

const SECTIONS: &[(&str, &[(&str, &str)])] = &[
    (
        "General",
        &[
            ("Tab", "switch between the left pane and the table"),
            ("1 / 2", "left pane: value scan / pointer paths"),
            ("↑↓ j k", "move the selection"),
            ("PgUp PgDn g G", "move faster / to the ends"),
            ("p", "pick a process to attach to"),
            (":", "run a REPL command"),
            ("?", "this help"),
            ("q Esc", "back to the REPL"),
        ],
    ),
    (
        "Value scan",
        &[
            ("f", "first scan (100, between 1 10, unknown, ...)"),
            ("n", "next scan (93, changed, dec, dec-by 7, ...)"),
            ("t", "cycle the value type (before a scan)"),
            ("r", "discard the results"),
            ("a Enter", "add the selected result to the table"),
            ("Ctrl-C", "cancel a running scan"),
        ],
    ),
    (
        "Pointer scan",
        &[
            ("P", "pointer scan options for the selected address"),
            ("x", "filter paths against an address"),
            ("r", "discard the paths"),
            ("a Enter", "add the selected path to the table"),
        ],
    ),
    (
        "Address table",
        &[
            ("Space", "freeze / unfreeze"),
            ("e Enter", "write a value"),
            ("D", "edit the description"),
            ("d Del", "remove"),
        ],
    ),
    (
        "Structs",
        &[
            ("s", "edit struct definitions"),
            ("v", "view the selection as a struct (empty: hex)"),
            ("+ -", "pointer depth in the struct view"),
            ("[ ]", "scroll the struct view"),
        ],
    ),
];

/// A `width` x `height` rectangle centred in `area`, shrunk to fit.
pub fn popup(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}

pub fn draw(f: &mut Frame) {
    let mut lines = Vec::new();
    for (i, (title, keys)) in SECTIONS.iter().enumerate() {
        if i > 0 {
            lines.push(Line::raw(""));
        }
        lines.push(Line::from(Span::raw(*title).bold().fg(Color::Cyan)));
        for (key, what) in *keys {
            lines.push(Line::from(vec![
                Span::raw(format!("  {key:<14}")).bold(),
                Span::raw(*what),
            ]));
        }
    }
    let area = popup(f.area(), 64, lines.len() as u16 + 2);
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(lines).block(
            Block::bordered()
                .title(" Keys (any key to close) ")
                .border_style(Style::new().fg(Color::Cyan)),
        ),
        area,
    );
}
