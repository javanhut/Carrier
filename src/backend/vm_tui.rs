//! Embedded terminal pane for `carrier run -it`: the container's PTY output is
//! fed through a vt100 emulator and drawn inside a ratatui frame with a status
//! border. Keystrokes are encoded back to the guest PTY over the same vsock
//! channel. Ctrl-Q ends the session (the run is ephemeral — the VM dies with
//! this process).

use std::io::{Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ratatui::crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, poll, read};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, BorderType};
use tui_term::widget::PseudoTerminal;

pub fn session(fd: RawFd, title: &str) -> ! {
    let result = run(fd, title);
    ratatui::restore();
    if let Err(e) = result {
        eprintln!("carrier: terminal session: {e}");
        std::process::exit(1);
    }
    std::process::exit(0);
}

fn run(fd: RawFd, title: &str) -> std::io::Result<()> {
    let mut term = ratatui::init();
    let size = term.size()?;
    // Pane interior = frame minus the border on each side.
    let cols = size.width.saturating_sub(2).max(10);
    let rows = size.height.saturating_sub(2).max(3);

    let mut stream = unsafe { UnixStream::from_raw_fd(fd) };
    stream.write_all(format!("run-t\n{cols} {rows}\n").as_bytes())?;

    let parser = Arc::new(Mutex::new(vt100::Parser::new(rows, cols, 0)));
    let dirty = Arc::new(AtomicBool::new(true));
    let done = Arc::new(AtomicBool::new(false));

    // Guest -> emulator, in a thread (read blocks). EOF = container exited.
    let mut reader = stream.try_clone()?;
    {
        let (parser, dirty, done) = (parser.clone(), dirty.clone(), done.clone());
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        parser.lock().unwrap().process(&buf[..n]);
                        dirty.store(true, Ordering::Relaxed);
                    }
                }
            }
            done.store(true, Ordering::Relaxed);
        });
    }

    let title = format!(" ⬢ {title} ");
    while !done.load(Ordering::Relaxed) {
        if poll(Duration::from_millis(16))? {
            match read()? {
                Event::Key(key) if key.kind != KeyEventKind::Release => {
                    if key.code == KeyCode::Char('q')
                        && key.modifiers.contains(KeyModifiers::CONTROL)
                    {
                        break;
                    }
                    if let Some(bytes) = encode_key(&key) {
                        stream.write_all(&bytes)?;
                    }
                }
                Event::Resize(w, h) => {
                    // ponytail: resizes the emulator pane only — the guest PTY
                    // keeps its initial size (no in-band resize channel yet).
                    let (c, r) = (w.saturating_sub(2).max(10), h.saturating_sub(2).max(3));
                    parser.lock().unwrap().screen_mut().set_size(r, c);
                    dirty.store(true, Ordering::Relaxed);
                }
                Event::Paste(text) => stream.write_all(text.as_bytes())?,
                _ => {}
            }
            dirty.store(true, Ordering::Relaxed);
        }
        if dirty.swap(false, Ordering::Relaxed) {
            let parser = parser.lock().unwrap();
            let screen = parser.screen();
            term.draw(|f| {
                let block = Block::bordered()
                    .border_type(BorderType::Rounded)
                    .border_style(Style::new().fg(Color::DarkGray))
                    .title(Span::styled(
                        title.clone(),
                        Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                    ))
                    .title_bottom(
                        Span::styled(" Ctrl-Q quit ", Style::new().fg(Color::DarkGray))
                            .into_right_aligned_line(),
                    );
                f.render_widget(PseudoTerminal::new(screen).block(block), f.area());
            })?;
        }
    }
    Ok(())
}

/// Terminal input encoding for the guest PTY: the common keys a shell, editor,
/// or pager needs. Unhandled keys are dropped.
fn encode_key(key: &KeyEvent) -> Option<Vec<u8>> {
    let mut bytes = if key.modifiers.contains(KeyModifiers::ALT) {
        vec![0x1b]
    } else {
        Vec::new()
    };
    match key.code {
        KeyCode::Char(c) if key.modifiers.contains(KeyModifiers::CONTROL) => {
            bytes.push((c.to_ascii_lowercase() as u8) & 0x1f)
        }
        KeyCode::Char(c) => bytes.extend(c.to_string().into_bytes()),
        KeyCode::Enter => bytes.push(b'\r'),
        KeyCode::Tab => bytes.push(b'\t'),
        KeyCode::BackTab => bytes.extend(b"\x1b[Z"),
        KeyCode::Backspace => bytes.push(0x7f),
        KeyCode::Esc => bytes.push(0x1b),
        KeyCode::Up => bytes.extend(b"\x1b[A"),
        KeyCode::Down => bytes.extend(b"\x1b[B"),
        KeyCode::Right => bytes.extend(b"\x1b[C"),
        KeyCode::Left => bytes.extend(b"\x1b[D"),
        KeyCode::Home => bytes.extend(b"\x1b[H"),
        KeyCode::End => bytes.extend(b"\x1b[F"),
        KeyCode::PageUp => bytes.extend(b"\x1b[5~"),
        KeyCode::PageDown => bytes.extend(b"\x1b[6~"),
        KeyCode::Delete => bytes.extend(b"\x1b[3~"),
        KeyCode::Insert => bytes.extend(b"\x1b[2~"),
        _ => return None,
    }
    Some(bytes)
}
