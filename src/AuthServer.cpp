#include "AuthServer.hpp"

#include "Configuration.h"
#include "Log.hpp"

#include <curl/curl.h>
#include <jwt-cpp/jwt.h>
#include <map>
#include <mutex>
#include <rapidjson/document.h>


namespace
{
int const CALL_DOWN = 60 /* seconds */;

enum class AuthError {
    ok = 0,
    base_64_decoding_failed,
    token_is_invalid,
    unknown_key,
    cant_get_new_keys,
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

std::string getContent(char const* url)
{
    std::string buffer;
    CURL* curl = curl_easy_init();

    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);

        CURLcode res = curl_easy_perform(curl);

        if (res != CURLE_OK)
        {
            ap_log_error(LOG_MARK, APLOG_ERR, 0, nullptr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            buffer.clear();
        }

        curl_easy_cleanup(curl);
    }

    return buffer;
}

std::map<std::string, std::string> extractKeys(std::string const& content)
{
    std::map<std::string, std::string> keys;

    rapidjson::Document document;
    document.Parse(content.c_str());

    if (document.HasParseError())
    {
        ap_log_error(LOG_MARK, APLOG_ERR, 0, nullptr, "Parse error of json data");
        return keys;
    }

    for (auto it = document.MemberBegin(); it != document.MemberEnd(); ++it)
        if (it->name.IsString() && it->value.IsString())
            keys[it->name.GetString()] = it->value.GetString();

    return keys;
}

std::map<std::string, std::string> getKeysFromServer()
{
    return extractKeys(getContent(configuration.server_url));
}
} // namespace

class AuthServer::Impl
{
public:
    [[nodiscard]] std::string getKey(std::string const& id, std::error_code& error_code)
    {
        std::lock_guard<std::mutex> lock_guard(mutex_);

        auto key = findKey(id);
        if (key.empty())
        {
            error_code = downloadKeys();
            if (!error_code)
            {
                key = findKey(id);
                if (key.empty())
                    error_code = make_error_code(AuthError::unknown_key);
            }
        }

        return key;
    }
private:
    std::map<std::string, std::string> known_keys_;
    time_t last_request_ = 0;
    std::mutex mutex_;

    [[nodiscard]] std::string findKey(std::string const& id) const
    {
        auto const cert = known_keys_.find(id);
        if (cert == known_keys_.cend())
            return "";

        return cert->second;
    }

    [[nodiscard]] std::error_code downloadKeys()
    {
        auto current_time = time(nullptr);
        if (current_time - last_request_ < CALL_DOWN)
            return make_error_code(AuthError::unknown_key);

        last_request_ = current_time;
        auto new_keys = getKeysFromServer();
        if (new_keys.empty())
            return make_error_code(AuthError::cant_get_new_keys);

        known_keys_ = new_keys;
        return make_error_code(AuthError::ok);
    }
};

AuthServer::AuthServer()
  : impl_(new Impl{})
{
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

AuthServer::~AuthServer()
{
    curl_global_cleanup();
}

AuthServer& AuthServer::instance()
{
    static AuthServer auth_server;
    return auth_server;
}

bool AuthServer::verify(char const* token, std::string& user, std::error_code& error_code)
{
    try
    {
        auto decoded = jwt::decode(token);
        auto const key = impl_->getKey(decoded.get_key_id(), error_code);

        if (error_code)
            return !error_code;

        auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::rs256{key})
                            .with_issuer(configuration.issuer)
                            .with_audience(configuration.client_id);

        verifier.verify(decoded, error_code);
        user = decoded.get_payload_claim("email").as_string();
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
