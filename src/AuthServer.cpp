#include "AuthServer.hpp"

#include "Configuration.h"

#include <cppcodec/base64_url_unpadded.hpp>
#include <curl/curl.h>
#include <http_log.h>
#include <jwt-cpp/jwt.h>
#include <map>
#include <mutex>
#include <rapidjson/document.h>

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(authg_jwt);
#endif

namespace
{
std::string const JWT_JKU_HEADER_NAME = "jku";
std::string const JWK_KEY_FORMAT = "jwk";

enum class AuthError {
    ok = 0,
    base_64_decoding_failed,
    token_is_invalid,
    unknown_key,
    cant_get_new_keys,
    untrusted_jku
};

std::error_category const& auth_error_category()
{
    class AuthErrorCategory : public std::error_category
    {
    public:
        [[nodiscard]] const char* name() const noexcept override
        {
            return "Auth Error";
        };

        [[nodiscard]] std::string message(int index) const override
        {
            switch (static_cast<AuthError>(index))
            {
            case AuthError::ok:
                return "no error";

            case AuthError::base_64_decoding_failed:
                return "Base64 decoding failed or invalid json";

            case AuthError::token_is_invalid:
                return "Token is not in correct format";

            case AuthError::unknown_key:
                return "Signed by unknown key";

            case AuthError::cant_get_new_keys:
                return "Can't get new keys from the server";

            case AuthError::untrusted_jku:
                return "jku is not a trusted host or jku uses an insecure protocol, consider configuring "
                       "AuthServerTrustedHosts in the apache config for the mod and switching to TLS for the jku "
                       "endpoint.";

            default:
                return "unknown type of error";
            }
        }
    };

    static AuthErrorCategory const category;
    return category;
}

std::error_code make_error_code(AuthError auth_error)
{
    return std::error_code{static_cast<int>(auth_error), auth_error_category()};
}

size_t writeCallback(char* content, size_t size, size_t nmb, void* u)
{
    ((std::string*)u)->append((char*)content, size * nmb);
    return size * nmb;
}

static int exact_stricmp(const char* a, const char* b)
{
    int ca, cb;
    do
    {
        ca = (unsigned char)*a++;
        cb = (unsigned char)*b++;
    } while (ca == cb && ca != '\0');
    return ca - cb;
}

std::string getContent(request_rec* r, char const* url)
{
    std::string buffer;
    CURL* curl = curl_easy_init();

    if (curl)
    {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "curl_easy_perform() on url: %s\n", url);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);

        CURLcode res = curl_easy_perform(curl);

        if (res != CURLE_OK)
        {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            buffer.clear();
        }

        curl_easy_cleanup(curl);
    }

    return buffer;
}

std::string getRSAPublicKeyInPEMFormat(request_rec* r, std::string_view nnInBase64UrlUnpadded,
                                       std::string_view eeInBase64UrlUnpadded)
{
    auto nnBin = cppcodec::base64_url_unpadded::decode(nnInBase64UrlUnpadded);
    auto eeBin = cppcodec::base64_url_unpadded::decode(eeInBase64UrlUnpadded);
    BIGNUM* modul = BN_bin2bn(nnBin.data(), nnBin.size(), NULL);
    BIGNUM* expon = BN_bin2bn(eeBin.data(), eeBin.size(), NULL);
    RSA* rsaKey = RSA_new();
#if defined(LWS_HAVE_RSA_SET0_KEY)
    RSA_set0_key(rsaKey, modul, expon, NULL);
#else
    rsaKey->e = expon;
    rsaKey->n = modul;
    rsaKey->d = NULL;
    rsaKey->p = NULL;
    rsaKey->q = NULL;
#endif
    BIO* mem = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(mem, rsaKey);
    BUF_MEM* bptr;
    BIO_get_mem_ptr(mem, &bptr);
    BIO_set_close(mem, BIO_NOCLOSE); /* So BIO_free() leaves BUF_MEM alone */
    BIO_free(mem);
    std::string pem = std::string(bptr->data);
    BUF_MEM_free(bptr);
    RSA_free(rsaKey);

    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "generated pem is:\n %s", pem.c_str());

    return pem;
}

// This is the complex case how keys can be provided, we have them as RFC compliant JWK Set in the server response
std::map<std::string, std::string> extractKeysFromJWKS(request_rec* r, rapidjson::Document const& document)
{
    std::map<std::string, std::string> keys;
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "We have JWK Format");
    // we have to convert JWK data to pem's -> exponent and modulo required for RS256/RS512 which is the only supported
    // algo as of today
    const char* KEYS_MEMBER = "keys";
    if (!document.HasMember(KEYS_MEMBER) && document[KEYS_MEMBER].IsArray())
    {
        // not RFC compliant
        ap_log_rerror(
            APLOG_MARK,
            APLOG_ERR,
            0,
            r,
            "Returned data is no JWK Set. JSON member <keys> is missing or no array. Could not understand data.");
        return keys;
    }
    else
    {
        const auto& key_array = document[KEYS_MEMBER];
        for (auto one_key = key_array.Begin(); one_key != key_array.End(); ++one_key)
        {
            if (!one_key->IsObject())
            {
                ap_log_rerror(APLOG_MARK,
                              APLOG_ERR,
                              0,
                              r,
                              "Returned JWKS contains invalid key entries. <keys> array-entries are not objects. Could "
                              "not understand data.");
                return keys;
            }
            if (!(one_key->HasMember("kid") && one_key->operator[]("kid").IsString()))
            {
                ap_log_rerror(
                    APLOG_MARK, APLOG_WARNING, 0, r, "Key has no kid, this is not RFC compliant. Ignoring this key.");
                continue;
            }
            const char* kid = one_key->operator[]("kid").GetString();

            if (!(one_key->HasMember("kty") && strcmp(one_key->operator[]("kty").GetString(), "RSA") == 0))
            {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Found non RSA key, ignoring key with id: %s.", kid);
                continue;
            }
            if (!(one_key->HasMember("n") && one_key->operator[]("n").IsString() && one_key->HasMember("e")
                  && one_key->operator[]("e").IsString()))
            {
                ap_log_rerror(APLOG_MARK,
                              APLOG_WARNING,
                              0,
                              r,
                              "Non-RFC compliant key entry, n or e are missing. Ignoring this key with id: %s",
                              kid);
                continue;
            }

            const char* n = one_key->operator[]("n").GetString();
            const char* e = one_key->operator[]("e").GetString();

            keys[kid] = getRSAPublicKeyInPEMFormat(r, n, e);
        }
    }

    return keys;
}

// This is the easy case how keys can be provided, we have directly pem/certs in the server response
std::map<std::string, std::string> extractKeysFromCert(request_rec* r, rapidjson::Document const& document)
{
    std::map<std::string, std::string> keys;
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "We have CERT/PEM Format already.");
    for (auto it = document.MemberBegin(); it != document.MemberEnd(); ++it)
        if (it->name.IsString() && it->value.IsString())
            keys[it->name.GetString()] = it->value.GetString();

    return keys;
}

std::map<std::string, std::string> extractKeys(request_rec* r, std::string const& content)
{
    std::map<std::string, std::string> keys;

    rapidjson::Document document;
    document.Parse(content.c_str());

    if (document.HasParseError())
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Parse error of json data");
        return keys;
    }

    // we might have certificates/pem or a JWK Set here...
    if (configuration.key_format && configuration.key_format == JWK_KEY_FORMAT)
    {
        keys = extractKeysFromJWKS(r, document);
    }
    else
    {
        keys = extractKeysFromCert(r, document);
    }

    return keys;
}

std::map<std::string, std::string> getKeysFromServer(request_rec* r, const char* url)
{
    return extractKeys(r, getContent(r, url));
}
} // namespace


class AuthServer::Impl
{
public:
    [[nodiscard]] std::string getKey(request_rec* r, jwt::decoded_jwt<jwt::picojson_traits>& decoded_jwt,
                                     std::error_code& error_code)
    {
        std::lock_guard<std::mutex> lock_guard(mutex_);

        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Looking for key with id %s.", decoded_jwt.get_key_id().c_str());

        cleanUpKeyCacheWhenRequired();
        auto key = findKey(decoded_jwt.get_key_id());
        if (key.empty())
        {
            if (configuration.use_jku && decoded_jwt.has_header_claim(JWT_JKU_HEADER_NAME))
            {
                ap_log_rerror(APLOG_MARK,
                              APLOG_INFO,
                              0,
                              r,
                              "Getting keys from server based on jku header at %s.",
                              decoded_jwt.get_header_claim(JWT_JKU_HEADER_NAME).as_string().c_str());
                // get keys from jku header url
                auto jku = decoded_jwt.get_header_claim(JWT_JKU_HEADER_NAME).as_string();
                if (isValidJku(r, jku))
                {
                    error_code = downloadKeys(r, jku.c_str());
                }
                else
                {
                    ap_log_rerror(APLOG_MARK,
                                  APLOG_ERR,
                                  0,
                                  r,
                                  "received jku (%s) is not in list of trusted_hosts or jku uses insecure protocol.",
                                  jku.c_str());
                    error_code = make_error_code(AuthError::untrusted_jku);
                }
            }
            else
            {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Getting keys from server at %s", configuration.server_url);
                error_code = downloadKeys(r, configuration.server_url);
            }
            if (!error_code)
            {
                key = findKey(decoded_jwt.get_key_id());
                if (key.empty())
                    error_code = make_error_code(AuthError::unknown_key);
            }
        }

        return key;
    }

private:
    // Note: As Apache is forking child processes at will, there are multiple instances
    // of the MOD /a AuthServer running. So you will get other instances for requests
    // after a few seconds. This means, that you will have to select the config values
    // carefully.
    // The only way to prevent this is:
    // a) prevent forking in apache configuration -> get performance issues for user
    // or b) use shared memory or similar -> lots of work only to be done when having issues.
    std::map<std::string, std::string> known_keys_;
    time_t last_request_ = 0;
    time_t last_clean_ = time(nullptr);
    std::mutex mutex_;

    bool isValidJku(request_rec* r, std::string const& jku) const
    {
        if (configuration.trusted_hosts == NULL)
        {
            if (configuration.allow_insecure_jku)
            {
                ap_log_rerror(APLOG_MARK,
                              APLOG_ERR,
                              0,
                              r,
                              "Allowing unchecked jku. In production please configure trusted_hosts.");
                return true;
            }
            return false;
        }

        int i;
        for (i = 0; configuration.trusted_hosts[i] != NULL; i++)
        {
            auto host = std::string(configuration.trusted_hosts[i]);
            if (jku.find("https://" + host + ":") != std::string::npos
                || jku.find("https://" + host + "/") != std::string::npos)
            {
                return true;
            }
            if (configuration.allow_insecure_jku
                && (jku.find("http://" + host + ":") != std::string::npos
                    || jku.find("http://" + host + "/") != std::string::npos))
            {
                ap_log_rerror(APLOG_MARK,
                              APLOG_WARNING,
                              0,
                              r,
                              "Allowing insecure http jku. In production please configure allow_insecure_jku = false.");
                return true;
            }
        }

        return false;
    }


    void cleanUpKeyCacheWhenRequired()
    {
        // cleanup the key cache, this is required due to:
        // - when keys are expired or compromised and removed from the key provider (AuthServer), they should no longer
        // be trusted
        // - make sure we do not get to big key cache filling the memory because we never forget unused keys.
        auto current_time = time(nullptr);

        if (difftime(current_time, last_clean_) > configuration.key_cache_clean_seconds)
        {
            this->known_keys_.clear();
            last_request_ = 0;
            last_clean_ = current_time;
        }
    }

    [[nodiscard]] std::string findKey(std::string const& id) const
    {
        auto const cert = known_keys_.find(id);
        if (cert == known_keys_.cend())
            return "";

        return cert->second;
    }

    [[nodiscard]] std::error_code downloadKeys(request_rec* r, const char* url)
    {
        auto current_time = time(nullptr);

        if (difftime(current_time, last_request_) < configuration.min_refresh_wait)
            return make_error_code(AuthError::unknown_key);

        last_request_ = current_time;
        auto new_keys = getKeysFromServer(r, url);
        if (new_keys.empty())
            return make_error_code(AuthError::cant_get_new_keys);

        known_keys_.insert(new_keys.begin(), new_keys.end());
        return make_error_code(AuthError::ok);
    }
};

AuthServer::AuthServer()
    : impl_(new Impl())
{
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

AuthServer::~AuthServer()
{
    curl_global_cleanup();
}

bool AuthServer::verify(request_rec* r, char const* token, std::string& user, std::error_code& error_code)
{
    try
    {
        auto decoded = jwt::decode(token);

        const char* alg = decoded.get_algorithm().c_str();

        // check algo before doing more expensive work
        if (!(exact_stricmp("RS256", alg) == 0 || exact_stricmp("RS512", alg) == 0))
        {
            ap_log_rerror(APLOG_MARK,
                          APLOG_ERR,
                          0,
                          r,
                          "Sent JWT is signed by alg %s but we only support RS256 and RS512. Rejecting.",
                          alg);
            return false;
        }

        std::string pem_key = impl_->getKey(r, decoded, error_code);

        if (error_code)
            return !error_code;

        auto verifier = jwt::verify();

        // only set issuer to be validated when it is defined
        if (configuration.issuer)
        {
            verifier.with_issuer(configuration.issuer);
        }

        // only set client_id/aud to be validated when it is defined
        if (configuration.client_id)
        {
            verifier.with_audience(configuration.client_id);
        }

        // creating correct algo for verifier.
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "We have algo %s.", alg);
        if (exact_stricmp("RS512", alg) == 0)
        {
            verifier.allow_algorithm(jwt::algorithm::rs512{pem_key});
        }
        else
        {
            verifier.allow_algorithm(jwt::algorithm::rs256{pem_key});
        }

        verifier.verify(decoded, error_code);

        if (error_code)
            return !error_code;

        if (configuration.user_claim)
        {
            ap_log_rerror(APLOG_MARK,
                          APLOG_DEBUG,
                          0,
                          r,
                          "Setting user to claim %s with value %s.",
                          configuration.user_claim,
                          decoded.get_payload_claim(configuration.user_claim).as_string().c_str());

            user = decoded.get_payload_claim(configuration.user_claim).as_string();
        }
        else
        {
            ap_log_rerror(APLOG_MARK,
                          APLOG_DEBUG,
                          0,
                          r,
                          "Default: Setting user to claim email with value %s.",
                          decoded.get_payload_claim("email").as_string().c_str());

            // defaults to email
            user = decoded.get_payload_claim("email").as_string();
        }
    }
    catch (std::invalid_argument&)
    {
        error_code = make_error_code(AuthError::token_is_invalid);
    }
    catch (std::runtime_error&)
    {
        error_code = make_error_code(AuthError::base_64_decoding_failed);
    }

    return !error_code;
}
