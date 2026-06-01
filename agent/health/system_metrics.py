"""
Ares Docker Agent - System Metrics

Lightweight CPU / memory sampling. Deliberately avoids a psutil dependency to
keep the security-audited, pinned requirement set minimal.

CPU is measured from the CONTAINER's own cgroup CPU accounting, averaged over
the interval since the previous reading (≈ the heartbeat cadence) — not a short
whole-host /proc/stat spot sample. The spot sample read ~0 on an idle Docker
Desktop VM and was unreliable under amd64 emulation; the cgroup counter is a
monotonic measure of CPU time actually consumed by this agent.
"""
import os
import time


def read_memory_percent() -> float:
    """Percentage of RAM in use (0-100), derived from /proc/meminfo."""
    try:
        info = {}
        with open("/proc/meminfo", "r") as f:
            for line in f:
                key, _, rest = line.partition(":")
                if rest:
                    info[key.strip()] = int(rest.strip().split()[0])  # value in kB

        total = info.get("MemTotal", 0)
        if not total:
            return 0.0

        # MemAvailable is the kernel's own estimate of allocatable memory and is
        # the right basis for "used%". Fall back to the classic computation on
        # older kernels that don't expose it.
        available = info.get("MemAvailable")
        if available is None:
            available = info.get("MemFree", 0) + info.get("Buffers", 0) + info.get("Cached", 0)

        used_pct = (1.0 - available / total) * 100.0
        return round(max(0.0, min(100.0, used_pct)), 1)
    except Exception:
        return 0.0


# Baseline for the interval-spanning cgroup CPU measurement (persists across
# calls within the agent process).
_prev_cpu = {"usage_s": None, "wall": None}


def _container_cpu_seconds():
    """Total CPU seconds consumed by THIS container so far (monotonic), from the
    cgroup CPU accounting. Returns None if cgroup accounting isn't available."""
    # cgroup v2 (Docker Desktop, modern hosts): /sys/fs/cgroup/cpu.stat
    try:
        with open("/sys/fs/cgroup/cpu.stat", "r") as f:
            for line in f:
                if line.startswith("usage_usec"):
                    return int(line.split()[1]) / 1_000_000.0
    except Exception:
        pass
    # cgroup v1: cpuacct.usage is in nanoseconds
    for path in ("/sys/fs/cgroup/cpuacct/cpuacct.usage",
                 "/sys/fs/cgroup/cpu,cpuacct/cpuacct.usage"):
        try:
            with open(path, "r") as f:
                return int(f.read().strip()) / 1_000_000_000.0
        except Exception:
            continue
    return None


def _cpu_pct_over(prev_usage, prev_wall, usage, wall):
    """CPU% of available cores between two (cpu_seconds, wall_monotonic) samples."""
    if prev_usage is None or prev_wall is None or wall <= prev_wall:
        return None
    ncpu = os.cpu_count() or 1
    pct = (usage - prev_usage) / ((wall - prev_wall) * ncpu) * 100.0
    return round(max(0.0, min(100.0, pct)), 1)


def _read_proc_stat_percent(interval: float) -> float:
    """Fallback only: whole-host CPU% over a short /proc/stat sample."""
    def times():
        with open("/proc/stat", "r") as f:
            for line in f:
                if line.startswith("cpu "):
                    fields = [int(x) for x in line.split()[1:]]
                    idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
                    return idle, sum(fields)
        return 0, 0
    try:
        idle1, total1 = times()
        time.sleep(interval)
        idle2, total2 = times()
        dt = total2 - total1
        if dt <= 0:
            return 0.0
        return round(max(0.0, min(100.0, (1.0 - (idle2 - idle1) / dt) * 100.0)), 1)
    except Exception:
        return 0.0


def read_cpu_percent(interval: float = 0.5) -> float:
    """This agent's CPU utilisation as a percent of available cores, averaged
    over the time since the previous call (≈ the heartbeat interval). The first
    call (no baseline) takes a brief inline sample so it isn't reported as 0.

    Blocking on the first call only — call via ``asyncio.to_thread`` from async
    contexts.
    """
    try:
        usage = _container_cpu_seconds()
        if usage is None:
            return _read_proc_stat_percent(interval)  # cgroup unavailable

        now = time.monotonic()
        prev_u, prev_w = _prev_cpu["usage_s"], _prev_cpu["wall"]
        _prev_cpu["usage_s"], _prev_cpu["wall"] = usage, now

        pct = _cpu_pct_over(prev_u, prev_w, usage, now)
        if pct is not None:
            return pct

        # No baseline yet (first heartbeat): take a short inline sample so we
        # return a real number now instead of 0.
        time.sleep(interval)
        usage2 = _container_cpu_seconds()
        now2 = time.monotonic()
        _prev_cpu["usage_s"], _prev_cpu["wall"] = usage2, now2
        return _cpu_pct_over(usage, now, usage2, now2) or 0.0
    except Exception:
        return 0.0
