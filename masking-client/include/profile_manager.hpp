#pragma once
#include <string>
#include <vector>
#include <map>
#include <stdexcept>

namespace masking_client {

// Connection profile selecting proxy circuit behaviour.
struct Profile {
    std::string name;       // e.g. "standard", "strict", "region-eu"
    std::string proxy_host; // ingress node address
    uint16_t    proxy_port; // ingress node SOCKS5 port
    bool        use_tls     = true;
    std::string region;     // optional region hint
};

// Manages named profiles stored in the local configuration file.
class ProfileManager {
public:
    explicit ProfileManager(const std::string& config_path);

    // Load all profiles from file.
    void load();

    // Persist all profiles to file.
    void save() const;

    // Return a profile by name; throws std::out_of_range if not found.
    const Profile& get(const std::string& name) const;

    // Add or update a profile.
    void set(Profile p);

    // Remove a profile by name.
    void remove(const std::string& name);

    // List all profile names.
    std::vector<std::string> names() const;

    // Currently active profile name (empty if none).
    const std::string& active() const { return active_; }
    void set_active(const std::string& name);

private:
    std::string                  config_path_;
    std::map<std::string, Profile> profiles_;
    std::string                  active_;
};

} // namespace masking_client
