#include "rate_limiter.hpp"
#include <algorithm>

namespace proxy_core {

RateLimiter::RateLimiter(uint32_t rate_cps, uint32_t burst_multiplier)
    : rate_(static_cast<double>(rate_cps)),
      burst_(static_cast<double>(rate_cps) * burst_multiplier) {}

void RateLimiter::refill(Bucket& b,
                          std::chrono::steady_clock::time_point now) const {
    double elapsed = std::chrono::duration<double>(now - b.last_refill).count();
    b.tokens = std::min(burst_, b.tokens + elapsed * rate_);
    b.last_refill = now;
}

bool RateLimiter::allow(const std::string& key) {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lk(mu_);

    auto it = buckets_.find(key);
    if (it == buckets_.end()) {
        buckets_[key] = {burst_ - 1.0, now};
        return true;
    }

    Bucket& b = it->second;
    refill(b, now);

    if (b.tokens >= 1.0) {
        b.tokens -= 1.0;
        return true;
    }
    return false;
}

void RateLimiter::evict_stale(uint32_t ttl_seconds) {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lk(mu_);
    for (auto it = buckets_.begin(); it != buckets_.end(); ) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(
                       now - it->second.last_refill).count();
        if (age > static_cast<long>(ttl_seconds))
            it = buckets_.erase(it);
        else
            ++it;
    }
}

void RateLimiter::reset() {
    std::lock_guard<std::mutex> lk(mu_);
    buckets_.clear();
}

} // namespace proxy_core
