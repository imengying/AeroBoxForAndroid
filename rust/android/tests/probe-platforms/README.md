# Standalone probe platforms

Run `:app:testRustProbePlatforms` or `bash rust/scripts/test-kotlin-probe-platforms.sh`
from the repository root. The actual `StandaloneProbePlatforms` and
`PhysicalNetworkCallbacks` classes run against Android/JNI boundary doubles.

Five cases cover overlapping probes sharing one monitor, a new probe selecting
the replacement network while an older probe remains busy, disconnection and
VPN rejection, recovery, failure cleanup, and a fresh context for a later batch.
The handover case checks the socket's selected network and the inventory default;
the native DNS/lifetime transition is verified separately in `platform_dns.rs`.
These checks do not claim device handover or Private DNS verification.
