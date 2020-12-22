#include "AuthServer.hpp"

#include "Configuration.h"

#include <curl/curl.h>
#include <http_log.h>
#include <jwt-cpp/jwt.h>
#include <rapidjson/document.h>

#define LOG_MARK __FILE__, __LINE__, -1


namespace
{
class TokenErrorCategory : public std::error_category
{
public:
    [[nodiscard]] const char* name() const noexcept override
    {
        return "Token Error";
    };

    [[nodiscard]] std::string message(int /* index */) const override
    {
        return "Key ID is not known";
    }
};

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
} // namespace

AuthServer::AuthServer()
{
    curl_global_init(CURL_GLOBAL_DEFAULT);

    known_keys_ = getKeys();
}

AuthServer::~AuthServer()
{
    curl_global_cleanup();
}

AuthServer& AuthServer::instance()
{
    static AuthServer authServer;
    return authServer;
}

bool AuthServer::verify(char const* token, std::string* user, std::error_code* error_code)
{
    auto decoded = jwt::decode(token);

    auto cert = known_keys_.find(decoded.get_key_id());
    if (cert == known_keys_.cend())
    {
        *error_code = std::error_code{0, TokenErrorCategory{}};
        return false;
    }

    auto verifier = jwt::verify()
                        .allow_algorithm(jwt::algorithm::rs256{cert->second})
                        .with_issuer(configuration.issuer)
                        .with_audience(configuration.client_id);

    verifier.verify(decoded, *error_code);
    *user = decoded.get_payload_claim("email").as_string();

    return !(*error_code);
}

std::map<std::string, std::string> AuthServer::getKeys() const
{
    return extractKeys(getContent("https://www.googleapis.com/oauth2/v1/certs"));
}
