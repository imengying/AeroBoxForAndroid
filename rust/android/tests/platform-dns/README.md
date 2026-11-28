# Platform DNS cancellation boundary

Run `bash scripts/test-kotlin-platform-dns.sh`. The production
`PlatformDnsQueries.kt` is compiled against minimal Android/JNI test doubles;
no native library is loaded and no Android resolver behavior is simulated as
verified device behavior.

Seven groups cover synchronous NXDOMAIN packet completion, duplicate callbacks,
cancel without Android callback, callback racing signal cancellation, physical
epoch invalidation, transport close, global-facing 64-request cap, invalid input,
partial submission failure, errno propagation and malformed/stale responses.
A delayed network-invalidation notification preserves requests already submitted
in the new epoch, and synchronous completion wins over a later submission error.
The tests also verify the full unsigned Long bit pattern is retained.

Android Private DNS operation and network-scoped resolution still require device
validation. Production Kotlin is separately compiled with the Android SDK by the app Gradle build.
