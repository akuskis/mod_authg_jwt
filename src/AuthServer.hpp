#pragma once

#include <memory>
#include <system_error>

#include <httpd.h>

class AuthServer
{
public:
    AuthServer();
    ~AuthServer();

    bool verify(request_rec* r, char const* token, std::string& user, std::error_code& error_code);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
