"""
Ares Docker Agent - System Metrics

Lightweight CPU / memory sampling straight from /proc. Deliberately avoids a
psutil dependency to keep the security-audited, pinned requirement set minimal
(matches the existing /proc reads in registration.client.get_system_info and
health.checker.get_uptime_seconds).
"""
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


def _read_cpu_times():
    """Return (idle, total) jiffies from the aggregate 'cpu' line of /proc/stat."""
    with open("/proc/stat", "r") as f:
        for line in f:
            if line.startswith("cpu "):
                fields = [int(x) for x in line.split()[1:]]
                # user nice system idle iowait irq softirq steal guest guest_nice
                idle = fields[3] + (fields[4] if len(fields) > 4 else 0)  # idle + iowait
                total = sum(fields)
                return idle, total
    return 0, 0


def read_cpu_percent(interval: float = 0.5) -> float:
    """Whole-host CPU utilisation (0-100), sampled over ``interval`` seconds.

    Blocking — call via ``asyncio.to_thread`` from async contexts so the short
    sleep doesn't stall the event loop.
    """
    try:
        idle1, total1 = _read_cpu_times()
        time.sleep(interval)
        idle2, total2 = _read_cpu_times()

        delta_total = total2 - total1
        delta_idle = idle2 - idle1
        if delta_total <= 0:
            return 0.0

        busy_pct = (1.0 - delta_idle / delta_total) * 100.0
        return round(max(0.0, min(100.0, busy_pct)), 1)
    except Exception:
        return 0.0
