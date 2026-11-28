#!/usr/bin/env python3
"""Audit active product dependencies, optionally inspect an Android shared library.

This examines normal/build target edges, rather than treating optional lockfile
entries or test-only Go peers as linked product dependencies.
"""
import argparse
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
BANNED = {
    "ring", "aws-lc-rs", "aws-lc-sys", "aws-lc-fips-sys", "openssl", "openssl-sys",
    "boring", "boring-sys", "libressl-src", "openssl-src", "libsodium-sys",
    "sodiumoxide", "mbedtls-sys-auto", "wolfssl-sys", "native-tls", "cronet",
    "libbox", "libz-sys", "libz-ng-sys", "cc", "cmake", "jemalloc-sys",
    "tikv-jemalloc-sys",
}
SYSTEM_LIBRARIES = {"libc.so", "libm.so", "libdl.so", "liblog.so", "libandroid.so"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=pathlib.Path,
                        default=ROOT / "crates/aerobox-android/Cargo.toml")
    parser.add_argument("--target", default="aarch64-linux-android")
    parser.add_argument("--library", type=pathlib.Path)
    args = parser.parse_args()
    command = ["cargo", "tree", "--locked", "--offline", "--manifest-path", str(args.manifest),
               "--target", args.target, "--edges", "normal,build", "--prefix", "none",
               "--format", "{p}"]
    result = subprocess.run(command, text=True, capture_output=True, cwd=ROOT)
    if result.returncode:
        sys.stderr.write(result.stderr)
        return result.returncode
    packages = sorted({line.split()[0] for line in result.stdout.splitlines() if line.strip()})
    prohibited = sorted(BANNED.intersection(packages))
    report = {"target": args.target, "active_packages": len(packages),
              "prohibited_packages": prohibited}
    if args.library:
        result = subprocess.run(["readelf", "-d", str(args.library)], text=True,
                                capture_output=True, check=True)
        needed = re.findall(r"\(NEEDED\).*\[([^]]+)\]", result.stdout)
        report["dynamic_libraries"] = needed
        report["non_system_libraries"] = sorted(set(needed) - SYSTEM_LIBRARIES)
    print(json.dumps(report, indent=2))
    return int(bool(prohibited or report.get("non_system_libraries")))


if __name__ == "__main__":
    raise SystemExit(main())
