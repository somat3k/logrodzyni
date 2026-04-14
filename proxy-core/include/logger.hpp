#pragma once
#include <string>
#include <mutex>
#include <memory>
#include <fstream>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace proxy_core {

enum class LogLevel { Debug = 0, Info, Warn, Error };

class Logger {
public:
    static Logger& instance() {
        static Logger inst;
        return inst;
    }

    void set_level(LogLevel lvl) { level_ = lvl; }
    void set_level(const std::string& s) {
        if (s == "debug") level_ = LogLevel::Debug;
        else if (s == "warn")  level_ = LogLevel::Warn;
        else if (s == "error") level_ = LogLevel::Error;
        else level_ = LogLevel::Info;
    }

    void open_file(const std::string& path) {
        std::lock_guard<std::mutex> lk(mu_);
        file_.open(path, std::ios::app);
    }

    template<typename... Args>
    void log(LogLevel lvl, Args&&... args) {
        if (lvl < level_) return;
        std::ostringstream oss;
        oss << timestamp() << " [" << level_str(lvl) << "] ";
        (oss << ... << args);
        oss << '\n';
        std::lock_guard<std::mutex> lk(mu_);
        auto& out = file_.is_open() ? file_ : std::cerr;
        out << oss.str();
        out.flush();
    }

    template<typename... Args> void debug(Args&&... args) { log(LogLevel::Debug, std::forward<Args>(args)...); }
    template<typename... Args> void info (Args&&... args) { log(LogLevel::Info,  std::forward<Args>(args)...); }
    template<typename... Args> void warn (Args&&... args) { log(LogLevel::Warn,  std::forward<Args>(args)...); }
    template<typename... Args> void error(Args&&... args) { log(LogLevel::Error, std::forward<Args>(args)...); }

private:
    Logger() = default;
    std::mutex    mu_;
    LogLevel      level_ = LogLevel::Info;
    std::ofstream file_;

    static std::string timestamp() {
        auto now = std::chrono::system_clock::now();
        auto t   = std::chrono::system_clock::to_time_t(now);
        std::ostringstream oss;
        oss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
        return oss.str();
    }
    static const char* level_str(LogLevel lvl) {
        switch (lvl) {
            case LogLevel::Debug: return "DEBUG";
            case LogLevel::Info:  return "INFO ";
            case LogLevel::Warn:  return "WARN ";
            case LogLevel::Error: return "ERROR";
        }
        return "?    ";
    }
};

#define LOG_DEBUG(...) proxy_core::Logger::instance().debug(__VA_ARGS__)
#define LOG_INFO(...)  proxy_core::Logger::instance().info (__VA_ARGS__)
#define LOG_WARN(...)  proxy_core::Logger::instance().warn (__VA_ARGS__)
#define LOG_ERROR(...) proxy_core::Logger::instance().error(__VA_ARGS__)

} // namespace proxy_core
