#pragma once

#include <memory>
#include <system_error>


class AuthServer
{
public:
    static AuthServer& instance();

    bool verify(char const* token, std::string& user, std::error_code& error_code);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;

    AuthServer();
    ~AuthServer();
};
