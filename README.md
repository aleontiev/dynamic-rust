# dynamic-rust

A reusable Rust implementation of the Dynamic REST wire protocol. It provides
resource metadata, permissions, query parsing, field selection, response
representations, relationship links, and sideloading primitives.

The core crate has no database driver or async web framework dependency. Hosts
provide resource schemas and implement `ResourceStore`; the optional `axum`
feature renders `ApiError` as an Axum response.

```toml
[dependencies]
dynamic-rust = { git = "https://github.com/aleontiev/dynamic-rust", features = ["axum"] }
```

Pin a full Git revision in production. This repository is the distribution source;
no crates.io release is implied.

Run `cargo test --all-features` and `cargo clippy --all-targets --all-features -- -D warnings`.
See [COMPATIBILITY.md](COMPATIBILITY.md) for implemented surfaces and limitations.

MIT license. Author: alonetiev@gmail.com.

## PostgreSQL application runtime

Enable the optional `application` feature for registered business models, CRUD,
transactional hooks/actions, durable tasks and shared app authentication. See
[the application guide](APPLICATION.md) and its executable integration tests.
