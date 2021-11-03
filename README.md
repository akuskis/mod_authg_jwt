# mod_authg_jwt
[![Build Status](https://travis-ci.org/akuskis/mod_authg_jwt.svg?branch=master)](https://travis-ci.org/akuskis/mod_authg_jwt)

Authentication module for Apache to verify JWT of Google OAuth2 or any other OIDC/oAuth2 compliant Identity Provider (Supports only RS256).

Verify JWT token and reject requests with invalid tokens with 401.
If it gets a JWT signed by an unknown key ID, then the mod will request the key from the identity provider / AuthServer. (Cool down of 60 seconds).

Supports server endpoints
- providing signing keys based on the jku JWT header or a known, fixed url.
- providing keys in pem format (certificate or public key) as well as JWKS format


## Simple setup
The following configuration is due in the apache main configuration (e.g. apache2.conf, httpd.conf or similar).

Module loading:
```
LoadModule authg_jwt_module modules/mod_authg_jwt.so
```

Configuring the module:
```
    AuthClientID ***.apps.googleusercontent.com
    AuthIssuer accounts.google.com
    AuthServer https://www.googleapis.com/oauth2/v1/certs
    AuthServerUseJku false
    AuthServerTrustedHosts hostname1, hostname2, hostnameN
    AuthServerAllowInsecureJku false
    AuthServerKeyFormat cert
    UserClaim email

    <Location /api/>
        AuthType JWT
        Require valid-user
    </Location>
```
Where the configuration options are:
- AuthClientID: The audience (aud) claim expected to be present during JWT validation. Ignored when not set.
- AuthIssuer: The issuer (iss) claim expected to be present during JWT validation. Ignored when not set.
- AuthServer: The url from where the public signing keys required for signature validation are loaded from. See also AuthServerUseJku.
- AuthServerUseJku: Set this to true when using the JWT jku header value as url to get the public signing keys. The AuthServer url is then only used as fallback when receiving a JWT without jku header. Defaults to false.
- AuthServerTrustedHosts: Only required when using jku. lists the hosts trusted to provide public signing keys. Comma sparated list. Ignored when not set! Make sure this is no security issue in your case.
- AuthServerAllowInsecureJku: For test environments only. Allows jku using insecure http urls. Does not do hostcheck of jku when no hosts are configured. Defaults to false.
- AuthServerKeyFormat: The format how the AuthServer provides the signing keys. Options: jwk (server provides a JWK Set), cert (Server provides certificates or public key PEMs). Defaults to cert.
- UserClaim: The claim identifying the user. Typical options are email, sub. Defaults to email.

Note to enable this mod for your location, AuthType JWT must be configured.

## Build on host

Prepare environment:
```shell script
sudo apt install build-essential cmake apache2-dev libcurl4-openssl-dev
```

Get sources:
```shell script
git clone git@github.com:akuskis/mod_authg_jwt.git
cd mod_authg_jwt
git submodule update --init --recursive
```

Build sources:
```shell script
mkdir build && cd build
cmake .. && make mod_authg_jwt
```

## Build release in Docker

Get sources as it was described before and run the following (Docker should be installed):
```shell script
docker build -t mod_authg_jwt .
docker create --name mod_authg_jwt mod_authg_jwt
docker cp mod_authg_jwt:/app/build/src/libmod_authg_jwt.so .
docker rm -f mod_authg_jwt
```

## License

This project is licensed under the GPLv3 License - see the [LICENSE](LICENSE) file for details
