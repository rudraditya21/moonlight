use std::io::{self, Read, Write};

pub struct CompletionResult {
    pub start: usize,
    pub candidates: Vec<String>,
}

pub trait Completer {
    fn complete(&self, line: &str) -> CompletionResult;
}

pub fn read_line(
    prompt: &str,
    completer: &dyn Completer,
    history: &[String],
) -> io::Result<Option<String>> {
    if !is_tty() {
        let mut line = String::new();
        let bytes = io::stdin().read_line(&mut line)?;
        if bytes == 0 {
            return Ok(None);
        }
        return Ok(Some(line.trim_end().to_string()));
    }

    let _raw = RawMode::new()?;
    let mut stdout = io::stdout();
    let mut stdin = io::stdin();
    let mut line = String::new();
    let mut cursor = 0usize;
    let mut buf = [0u8; 1];
    let mut history_pos: Option<usize> = None;
    let mut history_original = String::new();

    print!("{}", prompt);
    stdout.flush()?;

    loop {
        let read = stdin.read(&mut buf)?;
        if read == 0 {
            return Ok(None);
        }
        let b = buf[0];
        match b {
            b'\r' | b'\n' => {
                print!("\r\n");
                stdout.flush()?;
                return Ok(Some(line));
            }
            0x03 => {
                // Ctrl+C
                print!("^C\r\n");
                stdout.flush()?;
                return Ok(Some(String::new()));
            }
            0x01 => {
                // Ctrl+A
                cursor = 0;
                render_line_with_cursor(prompt, &line, cursor, &mut stdout)?;
            }
            0x05 => {
                // Ctrl+E
                cursor = line.len();
                render_line_with_cursor(prompt, &line, cursor, &mut stdout)?;
            }
            0x7f | 0x08 => {
                // Backspace
                if cursor > 0 {
                    let new_cursor = prev_char_boundary(&line, cursor);
                    line.replace_range(new_cursor..cursor, "");
                    cursor = new_cursor;
                    render_line_with_cursor(prompt, &line, cursor, &mut stdout)?;
                }
            }
            b'\t' => {
                let (before, after) = line.split_at(cursor);
                let completion = completer.complete(before);
                if completion.candidates.is_empty() {
                    print!("\x07");
                    stdout.flush()?;
                    continue;
                }
                if completion.candidates.len() == 1 {
                    let candidate = &completion.candidates[0];
                    let new_before = apply_completion(before, completion.start, candidate);
                    line = format!("{}{}", new_before, after);
                    cursor = new_before.len();
                    render_line_with_cursor(prompt, &line, cursor, &mut stdout)?;
                } else {
                    let lcp = longest_common_prefix(&completion.candidates);
                    if lcp.len() > before.len().saturating_sub(completion.start) {
                        let new_before = apply_completion(before, completion.start, &lcp);
                        line = format!("{}{}", new_before, after);
                        cursor = new_before.len();
                        render_line_with_cursor(prompt, &line, cursor, &mut stdout)?;
                    } else {
                        print!("\r\n");
                        for candidate in completion.candidates {
                            print!("{}  ", candidate);
                        }
                        print!("\r\n");
                        render_line_with_cursor(prompt, &line, cursor, &mut stdout)?;
                    }
                }
            }
            0x1b => {
                if let Some(action) = read_escape_sequence(&mut stdin)? {
                    match action {
                        EscapeAction::Up => {
                            if history.is_empty() {
                                print!("\x07");
                                stdout.flush()?;
                                continue;
                            }
                            if history_pos.is_none() {
                                history_original = line.clone();
                                history_pos = Some(history.len() - 1);
                            } else if let Some(pos) = history_pos {
                                if pos > 0 {
                                    history_pos = Some(pos - 1);
                                }
                            }
                            if let Some(pos) = history_pos {
                                line = history[pos].clone();
                                cursor = line.len();
                                render_line_with_cursor(prompt, &line, cursor, &mut stdout)?;
                            }
                        }
                        EscapeAction::Down => {
                            if history_pos.is_none() {
                                print!("\x07");
                                stdout.flush()?;
                                continue;
                            }
                            if let Some(pos) = history_pos {
                                if pos + 1 < history.len() {
                                    history_pos = Some(pos + 1);
                                    line = history[pos + 1].clone();
                                } else {
                                    history_pos = None;
                                    line = history_original.clone();
                                }
                                cursor = line.len();
                                render_line_with_cursor(prompt, &line, cursor, &mut stdout)?;
                            }
                        }
                        EscapeAction::Left => {
                            if cursor > 0 {
                                cursor = prev_char_boundary(&line, cursor);
                                render_line_with_cursor(prompt, &line, cursor, &mut stdout)?;
                            }
                        }
                        EscapeAction::Right => {
                            if cursor < line.len() {
                                cursor = next_char_boundary(&line, cursor);
                                render_line_with_cursor(prompt, &line, cursor, &mut stdout)?;
                            }
                        }
                        EscapeAction::Delete => {
                            if cursor < line.len() {
                                let next = next_char_boundary(&line, cursor);
                                line.replace_range(cursor..next, "");
                                render_line_with_cursor(prompt, &line, cursor, &mut stdout)?;
                            }
                        }
                        EscapeAction::Home => {
                            cursor = 0;
                            render_line_with_cursor(prompt, &line, cursor, &mut stdout)?;
                        }
                        EscapeAction::End => {
                            cursor = line.len();
                            render_line_with_cursor(prompt, &line, cursor, &mut stdout)?;
                        }
                    }
                }
            }
            byte if byte >= 0x20 => {
                let ch = byte as char;
                line.insert(cursor, ch);
                cursor += ch.len_utf8();
                render_line_with_cursor(prompt, &line, cursor, &mut stdout)?;
            }
            _ => {}
        }
    }
}

fn apply_completion(base: &str, start: usize, candidate: &str) -> String {
    if start > base.len() {
        return base.to_string();
    }
    let mut out = String::new();
    out.push_str(&base[..start]);
    out.push_str(candidate);
    out
}

fn render_line_with_cursor(
    prompt: &str,
    line: &str,
    cursor: usize,
    stdout: &mut io::Stdout,
) -> io::Result<()> {
    print!("\r\x1b[2K{}{}", prompt, line);
    let prompt_width = visible_len(prompt);
    let cursor_width = line[..cursor].chars().count();
    let total = prompt_width + cursor_width;
    print!("\r\x1b[{}C", total);
    stdout.flush()
}

fn visible_len(text: &str) -> usize {
    let bytes = text.as_bytes();
    let mut i = 0;
    let mut count = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'[' {
            i += 2;
            while i < bytes.len() {
                let b = bytes[i];
                i += 1;
                if b >= b'@' && b <= b'~' {
                    break;
                }
            }
        } else {
            count += 1;
            i += 1;
        }
    }
    count
}

fn prev_char_boundary(s: &str, mut idx: usize) -> usize {
    if idx == 0 {
        return 0;
    }
    idx -= 1;
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

fn next_char_boundary(s: &str, mut idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    idx += 1;
    while idx < s.len() && !s.is_char_boundary(idx) {
        idx += 1;
    }
    idx
}

fn longest_common_prefix(items: &[String]) -> String {
    if items.is_empty() {
        return String::new();
    }
    let mut prefix = items[0].clone();
    for item in &items[1..] {
        while !item.starts_with(&prefix) {
            if prefix.is_empty() {
                return String::new();
            }
            prefix.pop();
        }
    }
    prefix
}

enum EscapeAction {
    Up,
    Down,
    Left,
    Right,
    Delete,
    Home,
    End,
}

fn read_escape_sequence(stdin: &mut io::Stdin) -> io::Result<Option<EscapeAction>> {
    let mut buf = [0u8; 1];
    if stdin.read(&mut buf)? == 0 {
        return Ok(None);
    }
    if buf[0] != b'[' {
        return Ok(None);
    }
    if stdin.read(&mut buf)? == 0 {
        return Ok(None);
    }
    match buf[0] {
        b'A' => Ok(Some(EscapeAction::Up)),
        b'B' => Ok(Some(EscapeAction::Down)),
        b'C' => Ok(Some(EscapeAction::Right)),
        b'D' => Ok(Some(EscapeAction::Left)),
        b'H' => Ok(Some(EscapeAction::Home)),
        b'F' => Ok(Some(EscapeAction::End)),
        b'3' => {
            if stdin.read(&mut buf)? == 0 {
                return Ok(None);
            }
            if buf[0] == b'~' {
                Ok(Some(EscapeAction::Delete))
            } else {
                Ok(None)
            }
        }
        _ => Ok(None),
    }
}

struct RawMode {
    original: libc::termios,
}

impl RawMode {
    fn new() -> io::Result<Self> {
        unsafe {
            let mut term = std::mem::MaybeUninit::<libc::termios>::uninit();
            if libc::tcgetattr(libc::STDIN_FILENO, term.as_mut_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            let original = term.assume_init();
            let mut raw = original;
            raw.c_lflag &= !(libc::ECHO | libc::ICANON | libc::ISIG);
            raw.c_iflag &= !(libc::IXON | libc::ICRNL);
            raw.c_cc[libc::VMIN] = 1;
            raw.c_cc[libc::VTIME] = 0;
            if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(RawMode { original })
        }
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.original);
        }
    }
}

fn is_tty() -> bool {
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
}
