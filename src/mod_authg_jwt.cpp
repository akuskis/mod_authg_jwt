#include "http_core.h"
#include "http_request.h"
#include "httpd.h"


static void register_hooks(apr_pool_t* pool);
static int auth_check_jwt_hook(request_rec* r);

[[maybe_unused]] module AP_MODULE_DECLARE_DATA authg_jwt_module
    = {STANDARD20_MODULE_STUFF, nullptr, nullptr, nullptr, nullptr, nullptr, register_hooks, 0};

static void register_hooks(apr_pool_t* /* pool */)
{
    ap_hook_check_authn(auth_check_jwt_hook, nullptr, nullptr, APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_CONF);
}

static int auth_check_jwt_hook(request_rec* r)
{
    if (!r || strncmp(ap_auth_type(r), "JWT", 3) != 0)
        return DECLINED;

    // TODO: validate and extract r->user;
    return HTTP_UNAUTHORIZED;
}
