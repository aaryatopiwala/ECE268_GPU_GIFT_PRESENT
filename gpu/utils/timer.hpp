#pragma once
#include <sys/time.h>
#include <cstdint>
#include <cstdio>
#include <string>

class Timer {
public:
    Timer() { _started = false; }

    /** Begin timing. */
    void start() {
        gettimeofday(&_startTime, nullptr);
        _lapTime  = _startTime;
        _started  = true;
    }

    /**
     * Returns milliseconds elapsed since start().
     * Does NOT stop the timer — you can call stopMs() multiple times.
     */
    long stopMs() const {
        struct timeval now{};
        gettimeofday(&now, nullptr);
        return _diff(_startTime, now);
    }

    /**
     * Returns milliseconds elapsed since the last lapMs() call (or start()
     * if lapMs() has not been called yet), then resets the lap reference.
     */
    long lapMs() {
        struct timeval now{};
        gettimeofday(&now, nullptr);
        long ms = _diff(_lapTime, now);
        _lapTime = now;
        return ms;
    }

    /** Returns elapsed microseconds (higher resolution). */
    long stopUs() const {
        struct timeval now{};
        gettimeofday(&now, nullptr);
        return _diffUs(_startTime, now);
    }

    /** True if start() has been called. */
    bool isRunning() const { return _started; }

private:
    struct timeval _startTime{};
    struct timeval _lapTime{};
    bool           _started;

    static long _diff(const struct timeval& a, const struct timeval& b) {
        long secs  = b.tv_sec  - a.tv_sec;
        long usecs = b.tv_usec - a.tv_usec;
        return (secs * 1000L) + (usecs / 1000L);
    }
    static long _diffUs(const struct timeval& a, const struct timeval& b) {
        long secs  = b.tv_sec  - a.tv_sec;
        long usecs = b.tv_usec - a.tv_usec;
        return (secs * 1000000L) + usecs;
    }
};

class ScopedTimer {
public:
    explicit ScopedTimer(const std::string& label, bool printOnDestroy = true)
        : _label(label), _print(printOnDestroy)
    {
        _timer.start();
    }

    ~ScopedTimer() {
        if (_print)
            fprintf(stdout, "[timer] %s: %ld ms\n", _label.c_str(), _timer.stopMs());
    }

    /** Read the elapsed time before scope ends. */
    long elapsedMs() const { return _timer.stopMs(); }

private:
    Timer       _timer;
    std::string _label;
    bool        _print;
};
