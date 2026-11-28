# Local HTTP/2 changes

This is h2 **0.4.20**, the version already present in the application lockfile,
from upstream commit `b0e890842ac16d3c76836fd4fcc06421acb15fa7`.
The upstream MIT license and HPACK fixtures are retained.

`client::Builder::chromium_connect_mode(true)` selects the Naive CONNECT behavior:
literal non-Huffman `:method`, conditional Huffman strings, dynamic indexing,
explicit header order and Chromium's stream-priority fields. It is disabled by
default, so ordinary HTTP/gRPC transports retain the upstream path.

The normal h2 unit suite and actual Naive carrier tests run in
`.github/scripts/run-regression-tests.sh`. Independent reference instructions are
in `rust/tests/reference/naive-profile-peer/README.md`.
