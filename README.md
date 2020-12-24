# mod_authg_jwt
[![Build Status](https://travis-ci.org/akuskis/mod_authg_jwt.svg?branch=master)](https://travis-ci.org/akuskis/mod_authg_jwt)

Authentication module for Apache to verify JWT of Google OAuth2 (RS256).

Verify JWT token and reject requests with invalid tokens.
If got unknown key ID, then server will be requested for updates with call down of 60 seconds.

## Simple setup

Module loading:

```
LoadModule authg_jwt_module modules/mod_authg_jwt.so
```

Usage:
```
    AuthClientID ***.apps.googleusercontent.com
    AuthIssuer accounts.google.com
    AuthServer https://www.googleapis.com/oauth2/v1/certs

    <Location /api/>
        AuthType JWT
        Require valid-user
    </Location>
```

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
