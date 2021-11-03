#include "Configuration.h"
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

struct Configuration configuration;

static int wal_stricmp(const char *a, const char *b) {
  int ca, cb;
  do {
     ca = (unsigned char) *a++;
     cb = (unsigned char) *b++;
     ca = tolower(toupper(ca));
     cb = tolower(toupper(cb));
   } while (ca == cb && ca != '\0');
   return ca - cb;
}

typedef struct {
    const char *start;
    size_t len;
} token;

static const char** split(const char *str, char sep)
{
    const char **array;
    unsigned int start = 0, stop, toks = 0, t, blanks_at_stop=0;
    token *tokens = malloc((strlen(str) + 1) * sizeof(token));
    for (stop = 0; str[stop]; stop++) {
        if (str[stop] == sep) {
            // we found a separator -> next token is complete
            tokens[toks].start = str + start;
            tokens[toks].len = stop - start - blanks_at_stop;
            toks++;
            start = stop + 1;
            blanks_at_stop = 0;
        } else {
            if (str[stop] == ' ')
            {
                // we found a blank, remove it from start/end
                if(start == stop){
                    start++;
                } else {
                    blanks_at_stop++;
                }
            }            
        }
    }
    /* Mop up the last token */
    tokens[toks].start = str + start;
    tokens[toks].len = stop - start - blanks_at_stop;
    toks++;
    array = malloc((toks + 1) * sizeof(char*));
    for (t = 0; t < toks; t++) {
        /* Calloc makes it null-terminated */
        char *token = calloc(tokens[t].len + 1, 1);
        memcpy(token, tokens[t].start, tokens[t].len);
        array[t] = token;
    }
    /* Add a sentinel */
    array[t] = NULL;
    free(tokens);
    return array;
}

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

static const char* set_server_url(cmd_parms* cmd, void* cfg, const char* arg)
{
    configuration.server_url = arg;
    return NULL;
}

static const char* set_use_jku(cmd_parms* cmd, void* cfg, const char* arg)
{
    configuration.use_jku = arg && wal_stricmp(arg,"true")==0;
    return NULL;
}

static const char* set_allow_insecure_jku(cmd_parms* cmd, void* cfg, const char* arg)
{
    configuration.allow_insecure_jku = arg && wal_stricmp(arg,"true")==0;
    return NULL;
}

static const char* set_trusted_hosts(cmd_parms* cmd, void* cfg, const char* arg)
{
    configuration.trusted_hosts = split(arg, ',');
    return NULL;
}

static const char* set_key_format(cmd_parms* cmd, void* cfg, const char* arg)
{
    configuration.key_format = arg;
    return NULL;
}

static const char* set_user_claim(cmd_parms* cmd, void* cfg, const char* arg)
{
    configuration.user_claim = arg;
    return NULL;
}

const command_rec configuration_directives[]
    = {AP_INIT_TAKE1("AuthClientID", set_auth_client_id, NULL, RSRC_CONF, "Required Audience/Client ID in the JWT. Defaults to null (=not checked)."),
       AP_INIT_TAKE1("AuthIssuer", set_auth_issuer, NULL, RSRC_CONF, "Required Issuer in the JWT. Defaults to null (=not checked)."),
       AP_INIT_TAKE1("AuthServer", set_server_url, NULL, RSRC_CONF, "Server URL with public signing keys (keyendpoint). No default."),
       AP_INIT_TAKE1("AuthServerUseJku", set_use_jku, NULL, RSRC_CONF, "Use the jku JWT header as primary means for URL with public signing keys (AuthServer is only Fallback). Options: true, false. Defaults to false."),
       AP_INIT_TAKE1("AuthServerTrustedHosts", set_trusted_hosts, NULL, RSRC_CONF, "Comma separated list of hosts trusted to provide public signing keys (must match the host of the host:port part of the jku header.) Only used when jku is enabled. Not setting these is most likely a security risk."),
       AP_INIT_TAKE1("AuthServerKeyFormat", set_key_format, NULL, RSRC_CONF, "Key format. Options jwk (=rfc 7517/JWK format), cert (=pem format). Defaults to cert."),
       AP_INIT_TAKE1("AuthServerAllowInsecureJku", set_allow_insecure_jku, NULL, RSRC_CONF, "Ignores host verification of jku when trusted_hosts are not defined. Allows http jku. Only use in test environments. Defaults to false."),
       AP_INIT_TAKE1("UserClaim", set_user_claim, NULL, RSRC_CONF, "The JWT claim containing the user identity. Typical options: sub, email. Defaults to email when null."),
       {NULL}};
