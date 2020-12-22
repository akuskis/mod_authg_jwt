#include "Configuration.h"


struct Configuration configuration;

static const char* set_auth_client_id(cmd_parms* cmd, void* cfg, const char* arg)
{
    configuration.client_id = arg;
    return NULL;
}

static const char* set_auth_issuer(cmd_parms* cmd, void* cfg, const char* arg)
{
    configuration.issuer = arg;
    return NULL;
}

const command_rec configuration_directives[]
    = {AP_INIT_TAKE1("AuthClientID", set_auth_client_id, NULL, RSRC_CONF, "Client ID"),
       AP_INIT_TAKE1("AuthIssuer", set_auth_issuer, NULL, RSRC_CONF, "Issuer"),
       {NULL}};
