use std::io::{self, Read, Write};

pub struct CompletionResult {
    pub start: usize,
    pub candidates: Vec<String>,
}

pub trait Completer {
    fn complete(&self, line: &str) -> CompletionResult;
}

pub fn read_line(prompt: &str, completer: &dyn Completer) -> io::Result<Option<String>> {
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
    let mut buf = [0u8; 1];

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
            0x7f | 0x08 => {
                if !line.is_empty() {
                    line.pop();
                    render_line(prompt, &line, &mut stdout)?;
                }
            }
            b'\t' => {
                let completion = completer.complete(&line);
                if completion.candidates.is_empty() {
                    print!("\x07");
                    stdout.flush()?;
                    continue;
                }
                if completion.candidates.len() == 1 {
                    let candidate = &completion.candidates[0];
                    apply_completion(&mut line, completion.start, candidate);
                    render_line(prompt, &line, &mut stdout)?;
                } else {
                    let lcp = longest_common_prefix(&completion.candidates);
                    if lcp.len() > line.len().saturating_sub(completion.start) {
                        apply_completion(&mut line, completion.start, &lcp);
                        render_line(prompt, &line, &mut stdout)?;
                    } else {
                        print!("\r\n");
                        for candidate in completion.candidates {
                            print!("{}  ", candidate);
                        }
                        print!("\r\n");
                        render_line(prompt, &line, &mut stdout)?;
                    }
                }
            }
            0x1b => {
                // Skip escape sequences (arrows).
                let mut seq = [0u8; 2];
                let _ = stdin.read(&mut seq);
            }
            byte if byte >= 0x20 => {
                line.push(byte as char);
                print!("{}", byte as char);
                stdout.flush()?;
            }
            _ => {}
        }
    }
}

fn apply_completion(line: &mut String, start: usize, candidate: &str) {
    if start > line.len() {
        return;
    }
    line.replace_range(start.., candidate);
}

fn render_line(prompt: &str, line: &str, stdout: &mut io::Stdout) -> io::Result<()> {
    print!("\r\x1b[2K{}{}", prompt, line);
    stdout.flush()
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
