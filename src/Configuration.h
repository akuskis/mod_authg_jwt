#pragma once

#include <apr_strings.h>
#include <http_core.h>
#include <http_request.h>
#include <httpd.h>
#include <stdbool.h>
#include <string.h>


struct Configuration
{
    // the audience expected in the JWT, null=ignore.
    const char* client_id;
    // the issuer expected in the JWT, null=ignore.
    const char* issuer;
    // the url where the key to verify the JWT signature is loaded from. No default.
    const char* server_url;
    // Use server_url only as a fallback (value=true), use the JWT jku header as primary means to get the url where the key for signature verification is loaded from. Defaults to false.
    bool use_jku;
     // Ignores host verification of jku when trusted_hosts are not defined. Allows http jku. Only use in test environments. Defaults to false.
    bool allow_insecure_jku;
    // List of hosts trusted to provide public signing keys (must match the host of the host:port part of the jku header.) Only used when jku is enabled.
    const char** trusted_hosts;
    // The format of the the key. options: jwk (=jwk format), cert (=pem format). Defaults to cert.
    const char* key_format;
    // The claim that identifies the user. Typical options: sub, email. defaults to email.
    const char* user_claim;
    // The minumal amount of seconds to wait before the jku / server_url is queried again for new keys. Defaults to 60s. May be set to 0 to always query when a key is not found.
    int min_refresh_wait;
};

extern struct Configuration configuration;

extern const command_rec configuration_directives[];
