use std::fmt;

#[derive(Debug, Clone)]
pub enum ParseError {
    UnterminatedQuote,
    InvalidEscape(char),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::UnterminatedQuote => write!(f, "unterminated quote"),
            ParseError::InvalidEscape(ch) => write!(f, "invalid escape: {ch}"),
        }
    }
}

impl std::error::Error for ParseError {}

pub fn tokenize(line: &str) -> Result<Vec<String>, ParseError> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;

    for ch in line.chars() {
        if escape {
            let escaped = match ch {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                '\\' => '\\',
                '\"' => '"',
                '\'' => '\'',
                ' ' => ' ',
                _ => return Err(ParseError::InvalidEscape(ch)),
            };
            current.push(escaped);
            escape = false;
            continue;
        }

        if in_double && ch == '\\' {
            escape = true;
            continue;
        }
        if !in_single && !in_double && ch == '\\' {
            escape = true;
            continue;
        }

        if in_single {
            if ch == '\'' {
                in_single = false;
            } else {
                current.push(ch);
            }
            continue;
        }
        if in_double {
            if ch == '"' {
                in_double = false;
            } else {
                current.push(ch);
            }
            continue;
        }

        match ch {
            '\'' => in_single = true,
            '"' => in_double = true,
            c if c.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(ch),
        }
    }

    if escape || in_single || in_double {
        return Err(ParseError::UnterminatedQuote);
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_basic() {
        let tokens = tokenize("use exploit/multi/handler").unwrap();
        assert_eq!(tokens, vec!["use", "exploit/multi/handler"]);
    }

    #[test]
    fn tokenize_quotes() {
        let tokens = tokenize("set RHOSTS \"10.0.0.1 10.0.0.2\"").unwrap();
        assert_eq!(tokens, vec!["set", "RHOSTS", "10.0.0.1 10.0.0.2"]);
    }
}
