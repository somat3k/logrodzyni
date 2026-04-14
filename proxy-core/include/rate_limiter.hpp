#pragma once
#include <cstdint>
#include <string>
#include <chrono>
#include <atomic>
#include <mutex>
#include <unordered_map>

namespace proxy_core {

// Token-bucket rate limiter, keyed by source IP string.
// Limits new connection attempts to `rate_cps` per second per IP.
class RateLimiter {
public:
    explicit RateLimiter(uint32_t rate_cps, uint32_t burst_multiplier = 3);

    // Returns true if the request is allowed, false if it should be rejected.
    bool allow(const std::string& key);

    // Remove stale buckets (idle longer than ttl_seconds). Call periodically.
    void evict_stale(uint32_t ttl_seconds = 60);

    // Reset all state (useful for tests).
    void reset();

private:
    struct Bucket {
        double   tokens;
        std::chrono::steady_clock::time_point last_refill;
    };

    double   rate_;   // tokens per second
    double   burst_;  // maximum bucket size
    std::mutex mu_;
    std::unordered_map<std::string, Bucket> buckets_;

    void refill(Bucket& b, std::chrono::steady_clock::time_point now) const;
};

} // namespace proxy_core
