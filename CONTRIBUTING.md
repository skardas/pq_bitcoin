# Contributing to PQ Bitcoin

Thank you for your interest in contributing to PQ Bitcoin!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<you>/pq_bitcoin.git`
3. Install dependencies:
   - Rust 1.85+ (`rustup update`)
   - SP1 toolchain: `curl -L https://sp1.succinct.xyz | bash && sp1up`
   - Foundry (for Solidity tests): `curl -L https://foundry.paradigm.xyz | bash && foundryup`

## Development

```bash
# Run all Rust tests
cargo test --workspace

# Run Solidity tests
cd contracts && forge test -vvv

# Format and lint
cargo fmt && cargo clippy --workspace

# Build SP1 program
cd program && cargo prove build

# Execute (dry-run, no proof)
cd script && cargo run --release --bin pq_bitcoin -- --execute
```

## Pull Requests

1. Create a feature branch: `git checkout -b feat/my-feature`
2. Make your changes
3. Ensure `cargo test --workspace` and `cargo clippy --workspace` pass
4. Submit a PR with a clear description

## Code Style

- Follow `rustfmt` defaults (run `cargo fmt`)
- All public APIs must have `///` doc comments
- Return `Result` from library functions — avoid `unwrap()` in lib code
- Use `expect()` with descriptive messages in binaries and zkVM programs

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.
