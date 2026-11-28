#!/usr/bin/env python3
"""Run this project's build under a single lock and cgroup memory limits."""
import errno
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[2]


def main():
    command = sys.argv[1:]
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        raise SystemExit("usage: scripts/run-bounded-build.py -- COMMAND [ARG ...]")
    state = ROOT / "rust/target/build-control"
    state.mkdir(parents=True, exist_ok=True)
    # CI elevates only to create the scope; compilers keep the invoking user's
    # ownership so signing, artifact upload and Gradle cache save can read/write.
    identity = []
    if os.geteuid() == 0 and os.environ.get("SUDO_UID") not in (None, "0"):
        uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
        for directory in (state.parent, state):
            os.chown(directory, uid, gid)
        identity = [f"--uid={uid}", f"--gid={gid}"]
    with (state / "build.lock").open("a") as lock:
        print("Waiting for AeroBox build slot", flush=True)
        fcntl.flock(lock, fcntl.LOCK_EX)
        # Keep all children of the command in one limit. A failed compiler must
        # not consume the remaining memory reserved for other host services.
        unit = f"aerobox-core-build-{os.getpid()}"
        environment = os.environ.copy()
        environment.update(CARGO_BUILD_JOBS="1", CARGO_INCREMENTAL="0")
        scope = [
            "systemd-run", "--scope", "--quiet", f"--unit={unit}", *identity,
            "--property=MemoryAccounting=yes", "--property=MemoryHigh=4608M",
            "--property=MemoryMax=5G", "--property=MemorySwapMax=1G",
            "--property=TasksMax=256", "--property=OOMPolicy=kill", "--",
            *command,
        ]
        print(f"Starting {unit}: RAM high=4.5 GiB max=5 GiB, swap max=1 GiB", flush=True)
        process = subprocess.Popen(scope, cwd=ROOT, env=environment)
        cgroup = Path('/sys/fs/cgroup/system.slice') / f'{unit}.scope'
        peak = 0
        swap_peak = 0
        events = {}
        monitor_errors = {}
        with (state / f'{unit}.jsonl').open('w') as log:
            while True:
                try:
                    current = int((cgroup / 'memory.current').read_text())
                    peak = max(peak, int((cgroup / 'memory.peak').read_text()))
                    swap = int((cgroup / 'memory.swap.current').read_text())
                    swap_peak = max(swap_peak, swap)
                    events = dict(line.split() for line in
                                  (cgroup / 'memory.events').read_text().splitlines())
                    log.write(json.dumps(dict(time=time.time(), current=current,
                                              peak=peak, swap=swap, events=events)) + '\n')
                    log.flush()
                except OSError as error:
                    # cgroupfs can return ENODEV after a short-lived scope exits,
                    # even if the file was opened before the scope disappeared.
                    # Sampling must never release the build lock before the
                    # supervised process has been reaped.
                    if error.errno not in (errno.ENOENT, errno.ENODEV, errno.ESRCH):
                        key = f"{error.errno}: {error.strerror}"
                        monitor_errors[key] = monitor_errors.get(key, 0) + 1
                try:
                    result = process.wait(timeout=1)
                    break
                except subprocess.TimeoutExpired:
                    continue
        (state / f'{unit}.json').write_text(json.dumps(dict(
            returncode=result, memory_peak_sampled_bytes=peak,
            swap_peak_sampled_bytes=swap_peak, events=events,
            monitor_errors=monitor_errors,
            memory_high_bytes=4608 * 1024**2, memory_max_bytes=5 * 1024**3,
            swap_max_bytes=1024**3), indent=2) + '\n')
        print(f'{unit}: exit={result}, observed RAM peak={peak / 1024**3:.2f} GiB',
              flush=True)
        return result


if __name__ == "__main__":
    raise SystemExit(main())
