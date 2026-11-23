@test
def _attempts_share_the_lifetime():
    auto budget = _DeadlineBudget._start(0.5, 1.25, 4000000000)
    assert budget._attempt_deadline(4000000000) == 4500000000
    assert budget._attempt_deadline(4499999999) == 4999999999
    assert budget._attempt_deadline(4750000000) == 5250000000
    assert budget._attempt_deadline(5000000000) == 5250000000

@test
def _lifetime_stays_expired():
    auto budget = _DeadlineBudget._start(1.0, 0.25, 4000000000)
    assert budget._attempt_deadline(4249999999) == 4250000000
    _expect_timeout(budget, 4250000000)
    _expect_timeout(budget, 4250000001)

def _expect_timeout(_DeadlineBudget budget, int64 now_ns):
    auto caught = False
    try:
        budget._attempt_deadline(now_ns)
    except Timeout:
        caught = True
    assert caught

@test
def _zero_duration_and_fractional_nanoseconds():
    auto zero = _DeadlineBudget._start(0.0, 0.0, 0)
    _expect_timeout(zero, 0)

    auto zero_attempt = _DeadlineBudget._start(-0.0, 2.0, 300)
    _expect_timeout(zero_attempt, 900)

    auto zero_lifetime = _DeadlineBudget._start(2.0, 0.0, 300)
    _expect_timeout(zero_lifetime, 900)

    auto fraction = _DeadlineBudget._start(0.0000000011, 0.000000004, 100)
    assert fraction._attempt_deadline(100) == 102
    assert fraction._attempt_deadline(103) == 104

    auto tiny = _DeadlineBudget._start(0.0000000001, 0.0000000001, 100)
    assert tiny._attempt_deadline(100) == 101

@test
def _durations_and_addition_saturate():
    auto limit = 9223372036854775807
    auto long_budget = _DeadlineBudget._start(1.0e300, 9223372036.854776, 0)
    assert long_budget._attempt_deadline(0) == limit
    assert long_budget._attempt_deadline(1) == limit

    auto near_limit = _DeadlineBudget._start(0.000000001, 1.0, limit - 2)
    assert near_limit._attempt_deadline(limit - 2) == limit - 1
    assert near_limit._attempt_deadline(limit - 1) == limit
    _expect_timeout(near_limit, limit)

def _reject_budget(f64 timeout, f64 lifetime, int64 now_ns):
    auto rejected = False
    try:
        _DeadlineBudget._start(timeout, lifetime, now_ns)
    except ValueError:
        rejected = True
    assert rejected

@test
def _invalid_durations_and_monotonic_times():
    for invalid in [-1.0, -0.0000000001, math.inf, -math.inf, math.nan]:
        _reject_budget(invalid, 1.0, 0)
        _reject_budget(1.0, invalid, 0)
    _reject_budget(1.0, 1.0, -1)

    auto budget = _DeadlineBudget._start(1.0, 1.0, 0)
    auto rejected = False
    try:
        budget._attempt_deadline(-1)
    except ValueError:
        rejected = True
    assert rejected

@test
def _deadline_check_at_and_after_expiry():
    auto deadline = 9007199254740993
    _check_deadline(deadline, deadline - 1)
    for now_ns in [deadline, deadline + 1]:
        auto caught = False
        try:
            _check_deadline(deadline, now_ns)
        except Timeout:
            caught = True
        assert caught
