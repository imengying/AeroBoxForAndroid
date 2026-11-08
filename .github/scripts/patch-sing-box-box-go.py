import hashlib
from pathlib import Path


path = Path("box.go")
text = path.read_text()
cache_old = (
    "\tif experimentalOptions.CacheFile != nil && experimentalOptions.CacheFile.Enabled || options.PlatformLogWriter != nil {\n"
    "\t\tneedCacheFile = true\n"
    "\t}\n"
)
cache_new = (
    "\tif experimentalOptions.CacheFile != nil && experimentalOptions.CacheFile.Enabled {\n"
    "\t\tneedCacheFile = true\n"
    "\t}\n"
)
traffic_old = "\tif needClashAPI || needAPIService || options.PlatformLogWriter != nil {\n"

cache_count = text.count(cache_old)
if cache_count != 1:
    raise SystemExit(
        f"Failed to patch needCacheFile condition in box.go: expected exactly 1 match, found {cache_count}. "
        "Review upstream sing-box box.go before releasing."
    )
traffic_count = text.count(traffic_old)
if traffic_count != 1:
    raise SystemExit(
        f"Failed to patch traffic manager condition in box.go: expected exactly 1 match, found {traffic_count}. "
        "Review upstream sing-box box.go before releasing."
    )
clash_marker = "\t\tvar clashDefaultMode string\n"
if text.count(clash_marker) != 1:
    raise SystemExit("Review upstream clash mode initialization before updating the diagnostics patch")
patched = text.replace(cache_old, cache_new, 1).replace(
    clash_marker, "\t}\n\tif needClashAPI || needAPIService {\n" + clash_marker, 1
)
if cache_old in patched or cache_new not in patched:
    raise SystemExit("Patch verification failed for box.go needCacheFile condition")
path.write_text(patched)

# Keep the upstream tracker, but collect connections only while diagnostics is visible.
for filename, digest in {
    "common/trafficcontrol/manager.go": "3a7bbc42a8f2ea12ae62920f4218af8c71c5b189383ffd50332f03004fc4abf4",
    "common/trafficcontrol/tracker.go": "573ecfc0a61658153e681d0b02ae956d8c84ec1f04fbbdb7d3509434b3c20287",
}.items():
    if hashlib.sha256(Path(filename).read_bytes()).hexdigest() != digest:
        raise SystemExit(f"Review upstream {filename} before updating the diagnostics patch")

manager = Path("common/trafficcontrol/manager.go")
source = manager.read_text().replace('"sync"', '"sync"\n\t"sync/atomic"', 1)
source = source.replace("type Manager struct {", "type Manager struct {\n\ttrackingEnabled atomic.Bool", 1)
source += "\nfunc (m *Manager) SetTrackingEnabled(enabled bool) {\n\tm.trackingEnabled.Store(enabled)\n\tif !enabled { m.Clear() }\n}\n"
source = source.replace("\tmetadata.ClosedAt = closedAt", "\tif !m.trackingEnabled.Load() {\n\t\tm.closedConnectionsAccess.Unlock()\n\t\treturn\n\t}\n\tmetadata.ClosedAt = closedAt", 1)
manager.write_text(source)

tracker = Path("common/trafficcontrol/tracker.go")
source = tracker.read_text()
for function, result in (("RoutedConnection", "conn"), ("RoutedPacketConnection", "conn"), ("RoutedFlow", "nil")):
    start = source.index(f"func (m *Manager) {function}(")
    body = source.index("{\n", start) + 2
    source = source[:body] + f"\tif !m.trackingEnabled.Load() {{ return {result} }}\n" + source[body:]
tracker.write_text(source)
