#pragma once

#include <apr_strings.h>
#include <http_core.h>
#include <http_request.h>
#include <httpd.h>


struct Configuration
{
    const char* client_id;
    const char* issuer;
};

extern struct Configuration configuration;

extern const command_rec configuration_directives[];
