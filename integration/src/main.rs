

#[allow(unused_imports)]
#[macro_use]
extern crate log;







fn main() {
    eprintln!(r#"Needs to be run with "cargo test --features integration -- --test-threads=1""#);
}

#[cfg(not(feature = "integration"))]
#[test]
fn integration_tests_disabled() {
    eprintln!(r#"Needs to be run with "cargo test --features integration -- --test-threads=1""#);
}

#[cfg(feature = "integration")]
#[cfg(test)]
mod tests;
