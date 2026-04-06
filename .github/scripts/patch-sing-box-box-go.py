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
clash_old = (
    "\tif experimentalOptions.ClashAPI != nil || options.PlatformLogWriter != nil {\n"
    "\t\tneedClashAPI = true\n"
    "\t}\n"
)
clash_new = (
    "\tif experimentalOptions.ClashAPI != nil {\n"
    "\t\tneedClashAPI = true\n"
    "\t}\n"
)

cache_count = text.count(cache_old)
if cache_count != 1:
    raise SystemExit(
        f"Failed to patch needCacheFile condition in box.go: expected exactly 1 match, found {cache_count}. "
        "Review upstream sing-box box.go before releasing."
    )
clash_count = text.count(clash_old)
if clash_count != 1:
    raise SystemExit(
        f"Failed to patch needClashAPI condition in box.go: expected exactly 1 match, found {clash_count}. "
        "Review upstream sing-box box.go before releasing."
    )
patched = text.replace(cache_old, cache_new, 1).replace(clash_old, clash_new, 1)
if cache_old in patched or cache_new not in patched:
    raise SystemExit("Patch verification failed for box.go needCacheFile condition")
if clash_old in patched or clash_new not in patched:
    raise SystemExit("Patch verification failed for box.go needClashAPI condition")
path.write_text(patched)
