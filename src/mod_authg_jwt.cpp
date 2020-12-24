#include "Configuration.h"
#include "AuthServer.hpp"

#include <apr_strings.h>
#include <http_core.h>
#include <http_request.h>
#include <http_log.h>
#include <httpd.h>

#define LOG_MARK __FILE__,__LINE__,-1

static void register_hooks(apr_pool_t* pool);
static int auth_check_jwt_hook(request_rec* r);

[[maybe_unused]] module AP_MODULE_DECLARE_DATA authg_jwt_module
    = {STANDARD20_MODULE_STUFF, nullptr, nullptr, nullptr, nullptr, configuration_directives, register_hooks, 0};

static void register_hooks(apr_pool_t* /* pool */)
{
    ap_hook_check_authn(auth_check_jwt_hook, nullptr, nullptr, APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_CONF);
}

static int verify_token(request_rec* r, char const* token)
{
    std::string user;
    std::error_code error_code;

    if (!AuthServer::instance().verify(token, user, error_code))
    {
        ap_log_rerror(LOG_MARK, APLOG_ERR, 0, r, "Verification issue: %s", error_code.message().c_str());
        return HTTP_UNAUTHORIZED;
    }

    r->user = apr_pstrdup(r->pool, user.c_str());

    return OK;
}

static int auth_check_jwt_hook(request_rec* r)
{
    if (!r || strncmp(ap_auth_type(r), "JWT", 3) != 0)
        return DECLINED;

    char* authorization_header = (char*)apr_table_get(r->headers_in, "Authorization");
    if (!authorization_header || strncmp(authorization_header, "Bearer ", 7) != 0)
    {
        ap_log_rerror(LOG_MARK, APLOG_ERR, 0, r, "Invalid Authorization->Bearer header");
        return HTTP_UNAUTHORIZED;
    }

    return verify_token(r, authorization_header + 7);
}
