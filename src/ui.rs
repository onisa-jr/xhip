use is_terminal::IsTerminal;

pub fn is_tty() -> bool {
    std::io::stdout().is_terminal()
}

pub fn bold(s: &str) -> String {
    if is_tty() {
        format!("\x1b[1m{}\x1b[0m", s)
    } else {
        s.to_string()
    }
}

pub fn cyan_bold(s: &str) -> String {
    if is_tty() {
        format!("\x1b[1;36m{}\x1b[0m", s)
    } else {
        s.to_string()
    }
}

pub fn green_bold(s: &str) -> String {
    if is_tty() {
        format!("\x1b[1;32m{}\x1b[0m", s)
    } else {
        s.to_string()
    }
}

pub fn yellow_bold(s: &str) -> String {
    if is_tty() {
        format!("\x1b[1;33m{}\x1b[0m", s)
    } else {
        s.to_string()
    }
}

pub fn red_bold(s: &str) -> String {
    if is_tty() {
        format!("\x1b[1;31m{}\x1b[0m", s)
    } else {
        s.to_string()
    }
}

pub fn dim(s: &str) -> String {
    if is_tty() {
        format!("\x1b[2m{}\x1b[0m", s)
    } else {
        s.to_string()
    }
}

pub fn print_header(title: &str) {
    let width = 70;
    let padding = width - 4 - title.chars().count();
    let border = "─".repeat(width - 2);

    println!();
    println!("╭{}╮", border);
    println!("│  {}{}│", cyan_bold(title), " ".repeat(padding));
    println!("╰{}╯", border);
}

pub fn print_item(label: &str, value: &str) {
    println!("  {:<15} {}", dim(label), bold(value));
}

pub fn print_success(label: &str, value: &str) {
    println!("  {:<15} {}", dim(label), green_bold(value));
}

pub fn print_warning(label: &str, value: &str) {
    println!("  {:<15} {}", dim(label), yellow_bold(value));
}
