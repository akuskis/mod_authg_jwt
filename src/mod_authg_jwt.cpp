#include <linux/version.h>

#include "AuthServer.hpp"
#include "Configuration.h"

#include <http_log.h>
#include <httpd.h>

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(authg_jwt);
#endif

namespace
{
char const* AUTH_PREFIX = "Bearer ";
int const AUTH_PREFIX_LEN = strlen(AUTH_PREFIX);

// Note: when using standard singleton pattern for C++ Apache never the less instanciates
// the Singleton multiple times as there are forked processes each running a MOD.
// That's why we better use a global here.
static AuthServer authServer;

int verify_token(request_rec* r, char const* token)
{
    std::string user;
    std::error_code error_code;

    if (!authServer.verify(r, token, user, error_code))
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Verification issue: %s", error_code.message().c_str());
        return HTTP_UNAUTHORIZED;
    }

    r->user = apr_pstrdup(r->pool, user.c_str());
    return OK;
}

bool is_verification_required(request_rec* r)
{
    return r && strncmp(ap_auth_type(r), "JWT", 3) == 0;
}

bool is_valid_auth_header(char const* content)
{
    return content && strncmp(content, AUTH_PREFIX, AUTH_PREFIX_LEN) == 0;
}

int auth_check_jwt_hook(request_rec* r)
{
    if (!is_verification_required(r))
        return DECLINED;

    char* authorization_header = (char*)apr_table_get(r->headers_in, "Authorization");
    if (!is_valid_auth_header(authorization_header))
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Invalid Authorization->Bearer header");
        return HTTP_UNAUTHORIZED;
    }

    return verify_token(r, authorization_header + AUTH_PREFIX_LEN);
}
} // namespace


static void register_hooks(apr_pool_t* /* pool */)
{
    ap_hook_check_authn(auth_check_jwt_hook, nullptr, nullptr, APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_CONF);
}

#ifdef RHEL_MAJOR
// at least RHEL 7.9 and earlier have one parameter less
[[maybe_unused]] module AP_MODULE_DECLARE_DATA authg_jwt_module
    = {STANDARD20_MODULE_STUFF, nullptr, nullptr, nullptr, nullptr, configuration_directives, register_hooks};
#else
[[maybe_unused]] module AP_MODULE_DECLARE_DATA authg_jwt_module
    = {STANDARD20_MODULE_STUFF, nullptr, nullptr, nullptr, nullptr, configuration_directives, register_hooks, 0};
#endif