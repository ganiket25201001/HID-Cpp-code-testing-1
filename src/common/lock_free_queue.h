#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <optional>

namespace hidshield {

// Single-producer/single-consumer lock-free ring buffer for hot path events.
template <typename T, std::size_t Capacity>
class LockFreeQueue final {
public:
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be power of two");

    bool TryPush(const T& value) noexcept {
        const auto head = head_.load(std::memory_order_relaxed);
        const auto next = (head + 1U) & mask_;
        if (next == tail_.load(std::memory_order_acquire)) {
            return false;
        }
        buffer_[head] = value;
        head_.store(next, std::memory_order_release);
        return true;
    }

    std::optional<T> TryPop() noexcept {
        const auto tail = tail_.load(std::memory_order_relaxed);
        if (tail == head_.load(std::memory_order_acquire)) {
            return std::nullopt;
        }
        T value = buffer_[tail];
        tail_.store((tail + 1U) & mask_, std::memory_order_release);
        return value;
    }

    [[nodiscard]] std::size_t Size() const noexcept {
        const auto head = head_.load(std::memory_order_acquire);
        const auto tail = tail_.load(std::memory_order_acquire);
        return (head - tail) & mask_;
    }

private:
    static constexpr std::size_t mask_ = Capacity - 1U;
    std::array<T, Capacity> buffer_{};
    std::atomic<std::size_t> head_{0U};
    std::atomic<std::size_t> tail_{0U};
};

}  // namespace hidshield
