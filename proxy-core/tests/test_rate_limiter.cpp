#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "rate_limiter.hpp"

using proxy_core::RateLimiter;

TEST_CASE("RateLimiter allows first N requests", "[rate_limiter]") {
    // 2 CPS, burst multiplier = 2 → burst = 4 tokens
    RateLimiter rl(2, 2);

    // First 4 requests should pass (burst).
    for (int i = 0; i < 4; ++i)
        REQUIRE(rl.allow("10.0.0.1") == true);

    // Fifth should be rejected.
    REQUIRE(rl.allow("10.0.0.1") == false);
}

TEST_CASE("RateLimiter is per-key", "[rate_limiter]") {
    RateLimiter rl(1, 2);
    REQUIRE(rl.allow("10.0.0.1") == true);
    REQUIRE(rl.allow("10.0.0.2") == true); // different key
}

TEST_CASE("RateLimiter reset clears all buckets", "[rate_limiter]") {
    RateLimiter rl(1, 1);
    rl.allow("1.2.3.4");
    rl.allow("1.2.3.4");
    rl.reset();
    // After reset, bucket is full again.
    REQUIRE(rl.allow("1.2.3.4") == true);
}
