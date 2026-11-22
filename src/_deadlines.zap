import math

# A budget shared by all queries in one resolution. Every attempt computes its
# deadline from the same lifetime limit and its own monotonic start time.
struct _DeadlineBudget:
    int64 _timeout_ns
    int64 _lifetime_deadline_ns

    def _start(f64 timeout, f64 lifetime, int64 now_ns) -> _DeadlineBudget:
        auto timeout_ns = _duration_ns(timeout)
        auto lifetime_ns = _duration_ns(lifetime)
        return _DeadlineBudget(timeout_ns, _add_duration(now_ns, lifetime_ns))

    def _attempt_deadline(self, int64 now_ns) -> int64:
        return min(_add_duration(now_ns, self._timeout_ns), self._lifetime_deadline_ns)

def _duration_ns(f64 seconds) -> int64:
    if not math.isfinite(seconds) or seconds < 0.0:
        raise ValueError("DNS duration must be finite and nonnegative")
    auto nanos = math.ceil(seconds * 1000000000.0)
    # 2^63 is exactly representable as f64; int64 max is rounded up to it.
    if nanos >= 9223372036854775808.0:
        return 9223372036854775807
    return int64(nanos)

def _add_duration(int64 now_ns, int64 duration_ns) -> int64:
    if now_ns < 0:
        raise ValueError("DNS monotonic timestamp must be nonnegative")
    auto limit = 9223372036854775807
    if duration_ns > limit - now_ns:
        return limit
    return now_ns + duration_ns
