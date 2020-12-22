#pragma once

#include <map>
#include <system_error>


class AuthServer
{
public:
    static AuthServer& instance();

    bool verify(char const* token, std::string* user, std::error_code* error_code);

private:
    std::map<std::string, std::string> known_keys_;

    AuthServer();
    ~AuthServer();

    [[nodiscard]] std::map<std::string, std::string> getKeys() const;
};
