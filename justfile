# qwencryptopals — run `just -l` to list all recipes.

# Trusted verification gate — fmt, test, then lint; the default recipe (defined first)
gate:
    cargo fmt
    cargo test
    cargo clippy --all-targets --all-features --locked -- -D warnings

# Run the full test suite
test:
    cargo test

# Run property tests with a higher proptest case count (default 500)
test-fuzz cases="500":
    PROPTEST_CASES={{cases}} cargo test

# Run one level's tests, e.g. `just lvl set1 l003`
lvl set level:
    cargo test sets::{{set}}::{{level}}

# Lint with clippy, treating any warning as an error
lint:
    cargo clippy --all-targets --all-features --locked -- -D warnings

# Reformat the source tree
fmt:
    cargo fmt

# Verify formatting without modifying files
fmt-check:
    cargo fmt --check

# Type-check without code generation
check:
    cargo check --locked

# Build the crate
build:
    cargo build --locked

# Build the local HTML docs (surfaces `missing_docs` errors too)
doc:
    cargo doc --no-deps
