//! Colored `carrier ps` output: ratatui widgets rendered one-shot into a
//! Buffer and emitted as ANSI lines. No alternate screen, no raw mode, no
//! cursor queries — it's ordinary scrollback output. The plain box output in
//! commands.rs remains the non-TTY path for scripts/pipes.

use ratatui::buffer::Buffer;
use ratatui::crossterm::style::{Attribute, Color as CColor, SetAttribute, SetForegroundColor};
use ratatui::crossterm::Command;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, BorderType, Cell, Padding, Row, Table, Widget};

pub struct Section {
    pub title: &'static str,
    pub headers: &'static [&'static str],
    /// One color per column; a STATUS column is re-colored per row.
    pub colors: &'static [Color],
    pub rows: Vec<Vec<String>>,
    pub empty_msg: &'static str,
}

fn ccolor(c: Color) -> CColor {
    match c {
        Color::Black => CColor::Black,
        Color::Red => CColor::DarkRed,
        Color::Green => CColor::DarkGreen,
        Color::Yellow => CColor::DarkYellow,
        Color::Blue => CColor::DarkBlue,
        Color::Magenta => CColor::DarkMagenta,
        Color::Cyan => CColor::DarkCyan,
        Color::Gray => CColor::Grey,
        Color::DarkGray => CColor::DarkGrey,
        Color::LightRed => CColor::Red,
        Color::LightGreen => CColor::Green,
        Color::LightYellow => CColor::Yellow,
        Color::LightBlue => CColor::Blue,
        Color::LightMagenta => CColor::Magenta,
        Color::LightCyan => CColor::Cyan,
        Color::White => CColor::White,
        Color::Rgb(r, g, b) => CColor::Rgb { r, g, b },
        Color::Indexed(i) => CColor::AnsiValue(i),
        Color::Reset => CColor::Reset,
    }
}

fn status_color(status: &str) -> Color {
    if status.starts_with("Up") {
        Color::Green
    } else if status.starts_with("Exited") {
        Color::Red
    } else {
        Color::Yellow
    }
}

const SPACING: u16 = 3;

/// Build the table widget plus the (width, height) it wants.
fn table(section: &Section) -> (Table<'static>, u16, u16) {
    let title = format!(" {} ({}) ", section.title, section.rows.len());
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(Color::DarkGray))
        .padding(Padding::horizontal(1))
        .title(Span::styled(
            title.clone(),
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));

    // Every column sized to its content: nothing truncates (the old fixed-width
    // tables chopped NAMES/STATUS).
    let widths: Vec<u16> = section
        .headers
        .iter()
        .enumerate()
        .map(|(i, h)| {
            section
                .rows
                .iter()
                .map(|r| r[i].len())
                .max()
                .unwrap_or(0)
                .max(h.len()) as u16
        })
        .collect();
    // columns + spacing between + border/padding on both sides
    let content = widths.iter().sum::<u16>() + SPACING * (widths.len() as u16 - 1);
    let width = (content + 4)
        .max(title.len() as u16 + 2)
        .max(section.empty_msg.len() as u16 + 4);
    // top border + header + rows (or the empty message line) + bottom border
    let height = section.rows.len().max(1) as u16 + 3;

    let status_col = section.headers.iter().position(|h| *h == "STATUS");
    let rows: Vec<Row> = section
        .rows
        .iter()
        .map(|r| {
            Row::new(r.iter().enumerate().map(|(i, cell)| {
                let color = if Some(i) == status_col {
                    status_color(cell)
                } else {
                    section.colors[i]
                };
                Cell::from(Span::styled(cell.clone(), Style::new().fg(color)))
            }))
        })
        .collect();

    let header = Row::new(section.headers.iter().map(|h| {
        Cell::from(Span::styled(
            *h,
            Style::new().fg(Color::White).add_modifier(Modifier::BOLD),
        ))
    }));
    let t = Table::new(rows, widths.iter().map(|w| Constraint::Length(*w)))
        .header(header)
        .column_spacing(SPACING)
        .block(block);
    (t, width, height)
}

/// Render each section to a buffer and print it as ANSI-styled lines.
pub fn render(sections: Vec<Section>) -> std::io::Result<()> {
    let term_width = match ratatui::crossterm::terminal::size() {
        Ok((w, _)) if w > 0 => w,
        _ => 120,
    };

    let mut out = String::new();
    for (si, section) in sections.iter().enumerate() {
        if si > 0 {
            out.push('\n');
        }
        let (widget, width, height) = table(section);
        let area = Rect::new(0, 0, width.min(term_width), height);
        let mut buf = Buffer::empty(area);
        widget.render(area, &mut buf);
        if section.rows.is_empty() {
            buf.set_string(
                2,
                2,
                section.empty_msg,
                Style::new().fg(Color::DarkGray).add_modifier(Modifier::ITALIC),
            );
        }

        for y in 0..area.height {
            let mut current = None;
            for x in 0..area.width {
                let cell = &buf[(x, y)];
                let style = (cell.fg, cell.modifier);
                if current != Some(style) {
                    let _ = SetAttribute(Attribute::Reset).write_ansi(&mut out);
                    if cell.fg != Color::Reset {
                        let _ = SetForegroundColor(ccolor(cell.fg)).write_ansi(&mut out);
                    }
                    if cell.modifier.contains(Modifier::BOLD) {
                        let _ = SetAttribute(Attribute::Bold).write_ansi(&mut out);
                    }
                    if cell.modifier.contains(Modifier::ITALIC) {
                        let _ = SetAttribute(Attribute::Italic).write_ansi(&mut out);
                    }
                    current = Some(style);
                }
                out.push_str(cell.symbol());
            }
            let _ = SetAttribute(Attribute::Reset).write_ansi(&mut out);
            out.push('\n');
        }
    }
    print!("{out}");
    Ok(())
}
