# Dynamic REST compatibility

This crate implements the protocol surfaces below. Host applications remain
responsible for execution, persistence, authentication and nested expansion.
It does not claim complete compatibility with every Dynamic REST implementation.

| Surface | Status | Executable coverage |
| --- | --- | --- |
| Single and plural envelopes | Implemented | `payload`, `response` tests |
| Pagination metadata | Implemented | counted and `exclude_count` tests |
| Bracketed query parsing | Implemented | filters, sort, include/exclude, combine, cursor, truthiness tests |
| Top-level field selection | Implemented | deferred fields, list fields, wildcard exclusion tests |
| Nested selection | Parsed | expansion must be supplied by the host serializer/store |
| Scalar representation | Implemented | files, datetimes, decimals, money tests |
| Role and field permissions | Implemented | ordered overrides and effective-resource tests |
| Resource metadata | Implemented | metadata and Python title behavior tests |
| Router identity and canonical paths | Implemented | registration and duplicate identity tests |
| Bulk payload recognition | Implemented | bare and enveloped bulk tests |
| Sideload merge/deduplication | Implemented | identity, merge, and primary-type collision tests |
| Relationship links | Implemented | self/default/static/disabled/sideload/exclusion tests; callable links remain host-resolved |
| Embedded relation rendering | In progress | nested expansion remains host-adapter work |
| Query execution | Host adapter | the crate parses an engine-neutral query plan |
| Persistence | Host adapter | `ResourceStore`; no database driver dependency |
| Authentication and tenancy | Host application | intentionally outside this crate |

`cargo test --all-features` and strict Clippy are the local conformance gate.
