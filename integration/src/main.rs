fn main() {
    eprintln!(r#"Needs to be run with "cargo test -- --test-threads=1 --ignored""#);
}

#[cfg(test)]
mod tests;
