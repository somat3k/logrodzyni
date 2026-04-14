#include "profile_manager.hpp"
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <algorithm>

namespace masking_client {

ProfileManager::ProfileManager(const std::string& config_path)
    : config_path_(config_path) {}

void ProfileManager::load() {
    std::ifstream f(config_path_);
    if (!f) return; // no file yet – start empty

    std::string line;
    Profile     current;
    bool        in_profile = false;

    auto commit = [&]() {
        if (in_profile && !current.name.empty())
            profiles_[current.name] = current;
        current = {};
        in_profile = false;
    };

    while (std::getline(f, line)) {
        // Strip comments.
        auto cmt = line.find('#');
        if (cmt != std::string::npos) line = line.substr(0, cmt);

        // Trim.
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        if (line.empty()) { commit(); continue; }

        if (line.front() == '[' && line.back() == ']') {
            commit();
            current.name = line.substr(1, line.size() - 2);
            in_profile   = true;
            continue;
        }

        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        auto trim = [](std::string& s) {
            s.erase(0, s.find_first_not_of(" \t"));
            s.erase(s.find_last_not_of(" \t") + 1);
        };
        trim(key); trim(val);

        if (key == "proxy_host")  current.proxy_host = val;
        else if (key == "proxy_port") current.proxy_port = static_cast<uint16_t>(std::stoi(val));
        else if (key == "use_tls")    current.use_tls    = (val == "true" || val == "1");
        else if (key == "region")     current.region      = val;
        else if (key == "active")     active_             = val;
    }
    commit();
}

void ProfileManager::save() const {
    std::ofstream f(config_path_);
    if (!f) throw std::runtime_error("Cannot write config: " + config_path_);
    f << "active = " << active_ << "\n\n";
    for (const auto& [name, p] : profiles_) {
        f << "[" << name << "]\n";
        f << "proxy_host  = " << p.proxy_host  << "\n";
        f << "proxy_port  = " << p.proxy_port  << "\n";
        f << "use_tls     = " << (p.use_tls ? "true" : "false") << "\n";
        f << "region      = " << p.region      << "\n\n";
    }
}

const Profile& ProfileManager::get(const std::string& name) const {
    return profiles_.at(name);
}

void ProfileManager::set(Profile p) {
    profiles_[p.name] = std::move(p);
}

void ProfileManager::remove(const std::string& name) {
    profiles_.erase(name);
    if (active_ == name) active_.clear();
}

std::vector<std::string> ProfileManager::names() const {
    std::vector<std::string> result;
    result.reserve(profiles_.size());
    for (const auto& [k, _] : profiles_) result.push_back(k);
    return result;
}

void ProfileManager::set_active(const std::string& name) {
    if (!profiles_.count(name))
        throw std::out_of_range("Profile not found: " + name);
    active_ = name;
}

} // namespace masking_client
