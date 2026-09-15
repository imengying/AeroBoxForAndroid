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
traffic_new = "\tif needClashAPI || needAPIService {\n"

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
patched = text.replace(cache_old, cache_new, 1).replace(traffic_old, traffic_new, 1)
if cache_old in patched or cache_new not in patched:
    raise SystemExit("Patch verification failed for box.go needCacheFile condition")
if traffic_old in patched or traffic_new not in patched:
    raise SystemExit("Patch verification failed for box.go traffic manager condition")
path.write_text(patched)
