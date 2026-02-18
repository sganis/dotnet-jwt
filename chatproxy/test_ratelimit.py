# chatproxy/test_ratelimit.py
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from ratelimit import (
    Limits,
    RateLimiter,
    limits_for_role,
    minute_bucket,
    pick_role,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cfg(rpm_admin=120, rpm_user=30, conc_admin=10, conc_user=3):
    """Return a minimal Settings-like object."""
    return SimpleNamespace(
        rl_user_rpm_admin=rpm_admin,
        rl_user_rpm_user=rpm_user,
        rl_conc_admin=conc_admin,
        rl_conc_user=conc_user,
    )


def _redis(incr_return=1):
    """Return a mock async Redis client with controllable INCR return value."""
    r = MagicMock()
    r.incr = AsyncMock(return_value=incr_return)
    r.expire = AsyncMock(return_value=True)
    r.decr = AsyncMock(return_value=0)
    return r


# ---------------------------------------------------------------------------
# pick_role
# ---------------------------------------------------------------------------

class TestPickRole:
    def test_admin_returned_when_present(self):
        assert pick_role(["llm:admin"]) == "llm:admin"

    def test_user_returned_when_no_admin(self):
        assert pick_role(["llm:user"]) == "llm:user"

    def test_admin_wins_over_user(self):
        assert pick_role(["llm:user", "llm:admin"]) == "llm:admin"

    def test_unknown_for_empty_list(self):
        assert pick_role([]) == "unknown"

    def test_unknown_for_unrecognised_roles(self):
        assert pick_role(["llm:viewer", "llm:guest"]) == "unknown"

    def test_accepts_set(self):
        assert pick_role({"llm:user"}) == "llm:user"

    def test_accepts_generator(self):
        roles = (r for r in ["llm:admin"])
        assert pick_role(roles) == "llm:admin"


# ---------------------------------------------------------------------------
# limits_for_role
# ---------------------------------------------------------------------------

class TestLimitsForRole:
    def test_admin_limits(self):
        lim = limits_for_role("llm:admin", _cfg())
        assert lim == Limits(rpm=120, conc=10)

    def test_user_limits(self):
        lim = limits_for_role("llm:user", _cfg())
        assert lim == Limits(rpm=30, conc=3)

    def test_unknown_falls_back_to_user_limits(self):
        lim = limits_for_role("unknown", _cfg())
        assert lim == Limits(rpm=30, conc=3)

    def test_reads_values_from_cfg(self):
        lim = limits_for_role("llm:admin", _cfg(rpm_admin=60, conc_admin=5))
        assert lim == Limits(rpm=60, conc=5)

    def test_user_cfg_values_respected(self):
        lim = limits_for_role("llm:user", _cfg(rpm_user=10, conc_user=1))
        assert lim == Limits(rpm=10, conc=1)


# ---------------------------------------------------------------------------
# minute_bucket
# ---------------------------------------------------------------------------

class TestMinuteBucket:
    def test_format_is_twelve_digits(self):
        bucket = minute_bucket(0.0)  # 1970-01-01 00:00 UTC
        assert bucket == "197001010000"
        assert len(bucket) == 12

    def test_same_second_same_bucket(self):
        ts = 1_700_000_000.0
        assert minute_bucket(ts) == minute_bucket(ts + 0.999)

    def test_different_minute_different_bucket(self):
        ts = 1_700_000_000.0
        assert minute_bucket(ts) != minute_bucket(ts + 60)

    def test_known_timestamp(self):
        # 2024-01-15 13:45:00 UTC  →  202401151345
        import calendar, datetime
        dt = datetime.datetime(2024, 1, 15, 13, 45, 0, tzinfo=datetime.timezone.utc)
        ts = calendar.timegm(dt.timetuple())
        assert minute_bucket(ts) == "202401151345"


# ---------------------------------------------------------------------------
# RateLimiter.check_and_incr_rpm
# ---------------------------------------------------------------------------

class TestCheckAndIncrRpm:
    async def test_first_request_sets_expire(self):
        r = _redis(incr_return=1)
        rl = RateLimiter(r)
        await rl.check_and_incr_rpm("llm:user", "alice", 30)
        r.expire.assert_awaited_once()
        _, args, _ = r.expire.mock_calls[0]
        assert args[1] == 120  # TTL

    async def test_subsequent_request_skips_expire(self):
        r = _redis(incr_return=2)
        rl = RateLimiter(r)
        await rl.check_and_incr_rpm("llm:user", "alice", 30)
        r.expire.assert_not_awaited()

    async def test_within_limit_no_exception(self):
        r = _redis(incr_return=30)
        rl = RateLimiter(r)
        await rl.check_and_incr_rpm("llm:user", "alice", 30)  # exactly at limit

    async def test_over_limit_raises_429(self):
        r = _redis(incr_return=31)
        rl = RateLimiter(r)
        with pytest.raises(HTTPException) as exc_info:
            await rl.check_and_incr_rpm("llm:user", "alice", 30)
        assert exc_info.value.status_code == 429
        assert exc_info.value.detail == "Rate limit exceeded"

    async def test_key_contains_role_user_and_bucket(self):
        r = _redis(incr_return=1)
        rl = RateLimiter(r)
        with patch("ratelimit.time") as mock_time:
            mock_time.time.return_value = 0.0
            mock_time.gmtime = __import__("time").gmtime
            mock_time.strftime = __import__("time").strftime
            await rl.check_and_incr_rpm("llm:user", "bob", 30)
        key = r.incr.call_args[0][0]
        assert key.startswith("rl:rpm:llm:user:bob:")

    async def test_admin_limit_used_correctly(self):
        r = _redis(incr_return=121)
        rl = RateLimiter(r)
        with pytest.raises(HTTPException) as exc_info:
            await rl.check_and_incr_rpm("llm:admin", "alice", 120)
        assert exc_info.value.status_code == 429


# ---------------------------------------------------------------------------
# RateLimiter.acquire_concurrency
# ---------------------------------------------------------------------------

class TestAcquireConcurrency:
    async def test_first_acquire_sets_expire(self):
        r = _redis(incr_return=1)
        rl = RateLimiter(r)
        await rl.acquire_concurrency("alice", 3)
        r.expire.assert_awaited_once()
        _, args, _ = r.expire.mock_calls[0]
        assert args[1] == 300

    async def test_subsequent_acquire_skips_expire(self):
        r = _redis(incr_return=2)
        rl = RateLimiter(r)
        await rl.acquire_concurrency("alice", 3)
        r.expire.assert_not_awaited()

    async def test_within_limit_no_exception(self):
        r = _redis(incr_return=3)
        rl = RateLimiter(r)
        await rl.acquire_concurrency("alice", 3)  # exactly at limit

    async def test_over_limit_raises_429(self):
        r = _redis(incr_return=4)
        rl = RateLimiter(r)
        with pytest.raises(HTTPException) as exc_info:
            await rl.acquire_concurrency("alice", 3)
        assert exc_info.value.status_code == 429
        assert exc_info.value.detail == "Too many concurrent requests"

    async def test_over_limit_rolls_back_decr(self):
        r = _redis(incr_return=4)
        rl = RateLimiter(r)
        with pytest.raises(HTTPException):
            await rl.acquire_concurrency("alice", 3)
        r.decr.assert_awaited_once_with("rl:conc:alice")

    async def test_within_limit_no_rollback(self):
        r = _redis(incr_return=1)
        rl = RateLimiter(r)
        await rl.acquire_concurrency("alice", 3)
        r.decr.assert_not_awaited()

    async def test_key_format(self):
        r = _redis(incr_return=1)
        rl = RateLimiter(r)
        await rl.acquire_concurrency("carol", 3)
        r.incr.assert_awaited_once_with("rl:conc:carol")


# ---------------------------------------------------------------------------
# RateLimiter.release_concurrency
# ---------------------------------------------------------------------------

class TestReleaseConcurrency:
    async def test_calls_decr(self):
        r = _redis()
        rl = RateLimiter(r)
        await rl.release_concurrency("alice")
        r.decr.assert_awaited_once_with("rl:conc:alice")

    async def test_swallows_redis_exception(self):
        r = MagicMock()
        r.decr = AsyncMock(side_effect=ConnectionError("Redis down"))
        rl = RateLimiter(r)
        # Must not raise
        await rl.release_concurrency("alice")

    async def test_swallows_generic_exception(self):
        r = MagicMock()
        r.decr = AsyncMock(side_effect=RuntimeError("unexpected"))
        rl = RateLimiter(r)
        await rl.release_concurrency("alice")
