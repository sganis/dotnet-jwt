# chat/test_ratelimit.py
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from ratelimit import (
    Limits,
    RateLimiter,
    limits_for_tier,
    minute_bucket,
    pick_tier,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cfg(rpm_basic=10, rpm_pro=30, rpm_max=120, conc_basic=1, conc_pro=3, conc_max=10):
    return SimpleNamespace(
        rl_rpm_basic=rpm_basic,
        rl_rpm_pro=rpm_pro,
        rl_rpm_max=rpm_max,
        rl_conc_basic=conc_basic,
        rl_conc_pro=conc_pro,
        rl_conc_max=conc_max,
    )


def _redis(incr_return=1):
    r = MagicMock()
    r.incr = AsyncMock(return_value=incr_return)
    r.expire = AsyncMock(return_value=True)
    r.decr = AsyncMock(return_value=0)
    return r


# ---------------------------------------------------------------------------
# pick_tier
# ---------------------------------------------------------------------------

class TestPickTier:
    MAX = {"max_group"}
    PRO = {"pro_group"}

    def test_max_tier_when_in_max_group(self):
        assert pick_tier({"max_group"}, self.MAX, self.PRO, "basic") == "max"

    def test_pro_tier_when_in_pro_group(self):
        assert pick_tier({"pro_group"}, self.MAX, self.PRO, "basic") == "pro"

    def test_max_wins_over_pro(self):
        assert pick_tier({"pro_group", "max_group"}, self.MAX, self.PRO, "basic") == "max"

    def test_default_tier_when_in_no_tier_group(self):
        assert pick_tier({"dep1"}, self.MAX, self.PRO, "basic") == "basic"

    def test_default_tier_for_empty_groups(self):
        assert pick_tier(set(), self.MAX, self.PRO, "basic") == "basic"

    def test_custom_default_tier(self):
        assert pick_tier({"dep1"}, self.MAX, self.PRO, "standard") == "standard"

    def test_empty_max_and_pro_sets_always_returns_default(self):
        assert pick_tier({"max_group"}, set(), set(), "basic") == "basic"

    def test_access_group_does_not_grant_tier(self):
        """Being in dep1 (access) does not affect tier selection."""
        assert pick_tier({"dep1", "dep2"}, self.MAX, self.PRO, "basic") == "basic"


# ---------------------------------------------------------------------------
# limits_for_tier
# ---------------------------------------------------------------------------

class TestLimitsForTier:
    def test_basic_limits(self):
        assert limits_for_tier("basic", _cfg()) == Limits(rpm=10, conc=1)

    def test_pro_limits(self):
        assert limits_for_tier("pro", _cfg()) == Limits(rpm=30, conc=3)

    def test_max_limits(self):
        assert limits_for_tier("max", _cfg()) == Limits(rpm=120, conc=10)

    def test_unknown_tier_falls_back_to_basic(self):
        assert limits_for_tier("unknown", _cfg()) == Limits(rpm=10, conc=1)

    def test_reads_cfg_values(self):
        assert limits_for_tier("max", _cfg(rpm_max=200, conc_max=20)) == Limits(rpm=200, conc=20)

    def test_tier_lookup_case_insensitive(self):
        assert limits_for_tier("MAX", _cfg()) == Limits(rpm=120, conc=10)
        assert limits_for_tier("Pro", _cfg()) == Limits(rpm=30, conc=3)


# ---------------------------------------------------------------------------
# minute_bucket
# ---------------------------------------------------------------------------

class TestMinuteBucket:
    def test_format_is_twelve_digits(self):
        bucket = minute_bucket(0.0)
        assert bucket == "197001010000"
        assert len(bucket) == 12

    def test_same_second_same_bucket(self):
        ts = 1_700_000_000.0
        assert minute_bucket(ts) == minute_bucket(ts + 0.999)

    def test_different_minute_different_bucket(self):
        ts = 1_700_000_000.0
        assert minute_bucket(ts) != minute_bucket(ts + 60)

    def test_known_timestamp(self):
        import calendar, datetime
        dt = datetime.datetime(2024, 1, 15, 13, 45, 0, tzinfo=datetime.timezone.utc)
        ts = calendar.timegm(dt.timetuple())
        assert minute_bucket(ts) == "202401151345"


# ---------------------------------------------------------------------------
# RateLimiter.check_rpm
# ---------------------------------------------------------------------------

class TestCheckRpm:
    async def test_first_request_sets_expire(self):
        r = _redis(incr_return=1)
        rl = RateLimiter(r)
        await rl.check_rpm("basic", "alice", 10)
        r.expire.assert_awaited_once()
        _, args, _ = r.expire.mock_calls[0]
        assert args[1] == 120

    async def test_subsequent_request_skips_expire(self):
        r = _redis(incr_return=2)
        rl = RateLimiter(r)
        await rl.check_rpm("basic", "alice", 10)
        r.expire.assert_not_awaited()

    async def test_within_limit_no_exception(self):
        r = _redis(incr_return=10)
        rl = RateLimiter(r)
        await rl.check_rpm("basic", "alice", 10)  # exactly at limit

    async def test_over_limit_raises_429(self):
        r = _redis(incr_return=11)
        rl = RateLimiter(r)
        with pytest.raises(HTTPException) as exc_info:
            await rl.check_rpm("basic", "alice", 10)
        assert exc_info.value.status_code == 429
        assert exc_info.value.detail == "Rate limit exceeded"

    async def test_key_contains_tier_user_and_bucket(self):
        r = _redis(incr_return=1)
        rl = RateLimiter(r)
        with patch("ratelimit.time") as mock_time:
            mock_time.time.return_value = 0.0
            mock_time.gmtime = __import__("time").gmtime
            mock_time.strftime = __import__("time").strftime
            await rl.check_rpm("pro", "bob", 30)
        key = r.incr.call_args[0][0]
        assert key.startswith("rl:rpm:pro:bob:")

    async def test_max_tier_limit_enforced(self):
        r = _redis(incr_return=121)
        rl = RateLimiter(r)
        with pytest.raises(HTTPException) as exc_info:
            await rl.check_rpm("max", "alice", 120)
        assert exc_info.value.status_code == 429


# ---------------------------------------------------------------------------
# RateLimiter.acquire_conc
# ---------------------------------------------------------------------------

class TestAcquireConc:
    async def test_first_acquire_sets_expire(self):
        r = _redis(incr_return=1)
        rl = RateLimiter(r)
        await rl.acquire_conc("basic", "alice", 3)
        r.expire.assert_awaited_once()
        _, args, _ = r.expire.mock_calls[0]
        assert args[1] == 300

    async def test_subsequent_acquire_skips_expire(self):
        r = _redis(incr_return=2)
        rl = RateLimiter(r)
        await rl.acquire_conc("basic", "alice", 3)
        r.expire.assert_not_awaited()

    async def test_within_limit_no_exception(self):
        r = _redis(incr_return=3)
        rl = RateLimiter(r)
        await rl.acquire_conc("basic", "alice", 3)  # exactly at limit

    async def test_over_limit_raises_429(self):
        r = _redis(incr_return=4)
        rl = RateLimiter(r)
        with pytest.raises(HTTPException) as exc_info:
            await rl.acquire_conc("basic", "alice", 3)
        assert exc_info.value.status_code == 429
        assert exc_info.value.detail == "Too many concurrent requests"

    async def test_over_limit_rolls_back_decr(self):
        r = _redis(incr_return=4)
        rl = RateLimiter(r)
        with pytest.raises(HTTPException):
            await rl.acquire_conc("basic", "alice", 3)
        r.decr.assert_awaited_once_with("rl:conc:basic:alice")

    async def test_within_limit_no_rollback(self):
        r = _redis(incr_return=1)
        rl = RateLimiter(r)
        await rl.acquire_conc("basic", "alice", 3)
        r.decr.assert_not_awaited()

    async def test_key_format(self):
        r = _redis(incr_return=1)
        rl = RateLimiter(r)
        await rl.acquire_conc("pro", "carol", 3)
        r.incr.assert_awaited_once_with("rl:conc:pro:carol")


# ---------------------------------------------------------------------------
# RateLimiter.release_conc
# ---------------------------------------------------------------------------

class TestReleaseConc:
    async def test_calls_decr_with_tier_and_user(self):
        r = _redis()
        rl = RateLimiter(r)
        await rl.release_conc("basic", "alice")
        r.decr.assert_awaited_once_with("rl:conc:basic:alice")

    async def test_tier_included_in_key(self):
        r = _redis()
        rl = RateLimiter(r)
        await rl.release_conc("max", "bob")
        r.decr.assert_awaited_once_with("rl:conc:max:bob")

    async def test_swallows_redis_exception(self):
        r = MagicMock()
        r.decr = AsyncMock(side_effect=ConnectionError("Redis down"))
        rl = RateLimiter(r)
        await rl.release_conc("basic", "alice")  # must not raise

    async def test_swallows_generic_exception(self):
        r = MagicMock()
        r.decr = AsyncMock(side_effect=RuntimeError("unexpected"))
        rl = RateLimiter(r)
        await rl.release_conc("basic", "alice")
