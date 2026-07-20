#pragma once

// Happy-path self-tests of the pure codec/math helpers: hex, base64url,
// amount splitting, NUT-10 secret parsing, and the V4 (CBOR) token
// round-trip. On-device, no NVS writes, no network; results logged at
// info level like the other suites. Returns true when all vectors pass.
bool nucula_pure_selftests();
