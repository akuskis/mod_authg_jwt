#pragma once

#include <map>
#include <mutex>
#include <system_error>


class AuthServer
{
public:
    static AuthServer& instance();

    bool verify(char const* token, std::string& user, std::error_code& error_code);

private:
    std::map<std::string, std::string> known_keys_;
    time_t last_request_ = 0;
    std::mutex mutex_;

    AuthServer();
    ~AuthServer();

    [[nodiscard]] std::string getKey(std::string const& id, std::error_code& error_code);
    [[nodiscard]] std::map<std::string, std::string> getKeys() const;

    [[nodiscard]] std::string findKey(std::string const& id) const;
    [[nodiscard]] std::error_code downloadKeys();
};
