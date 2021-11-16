# mod_authg_jwt
[![Build Status](https://travis-ci.org/akuskis/mod_authg_jwt.svg?branch=master)](https://travis-ci.org/akuskis/mod_authg_jwt)

Authentication module for Apache to verify JWT of Google OAuth2 or any other OIDC/oAuth2 compliant Identity Provider (Supports only RS256 / RS512).

Verify JWT token and reject requests with invalid tokens with 401.
If it gets a JWT signed by an unknown key ID, then the mod will request the key from the identity provider / AuthServer. (Cool down of 60 seconds).

Supports server endpoints
- providing signing keys based on the jku JWT header or a known, fixed url.
- providing keys in pem format (certificate or public key) as well as JWKS format


## Simple setup
The following configuration is due in the apache main configuration (e.g. apache2.conf, httpd.conf or similar, e.g. /etc/apache2/apache2.conf).

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
    MinKeyRefreshWait 30

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
- MinKeyRefreshWait: Requests the jku or AuthServer url only when there was no call for the last MinKeyRefreshWait seconds. Defaults to 60. Set to 0 to always query when the key was noz found in the local cache.

Note to enable this mod for your location, AuthType JWT must be configured.

Note also: You will have to restart apache with a command such as
```shell script
sudo systemctl restart apache2
```
after configuration.

Note: If authentication does not work as expected see the apache error log (e.g. /var/log/apache2/error.log) for hints on what is wrong with the configuration / received JWT.

## Build on host (for Ubuntu, GNU Linux, etc)

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

## Build on host (for Red Hat Enterprise Linux)

### Prepare for git
```shell script
sudo yum install git
```

### Get sources and sub-modules from git
```shell script
git clone https://github.com/akuskis/mod_authg_jwt.git
cd mod_authg_jwt
git submodule update --init --recursive
```

### prepare environemnt
Install cmake:
```shell script
sudo yum install cmake
```
Note if you have an old cmake version in your distribution you will have to manually install cmake 3.16. or higher.
```shell script
sudo yum remove cmake
cd /opt
sudo wget https://github.com/Kitware/CMake/releases/download/v3.21.4/cmake-3.21.4-linux-x86_64.sh
sudo sh ./cmake-3.21.4-linux-x86_64.sh
sudo ln -s /opt/cmake-3.21.4-linux-x86_64/bin/* /usr/local/bin
sudo ln -s /opt/cmake-3.21.4-linux-x86_64/bin/* /usr/bin
cmake -version
```

Install development dependencies:
This requires you to have a gcc compiler that supports C++ 17 features. If you are still on RHEL 7.x or below you will for sure require the RedHat devtool-chain. This requires you to have a (free for individuals) RedHat subscription.
(Note if you have a new RHEL-Version it might be sufficient to install "sudo yum groupinstall 'Development Tools'" instead of the toolchain. Check your gcc version.)

Here you can register for the RedHat developer program: https://developers.redhat.com/register .
Then you can see how to use the developer toolset: https://access.redhat.com/solutions/472793
See how to get your system registered: https://access.redhat.com/documentation/en-us/red_hat_subscription_management/1/html/quick_registration_for_rhel/index . For me this was simply "sudo subscription-manager register".
Then assign a subscription: https://access.redhat.com/solutions/776723
And add the repositories required: https://access.redhat.com/documentation/en-us/red_hat_developer_toolset/11/html/user_guide/chap-red_hat_developer_toolset#sect-Red_Hat_Developer_Toolset-Subscribe-RHSCL . For me this was "sudo subscription-manager repos --enable rhel-7-server-optional-rpms", "sudo subscription-manager repos --enable rhel-7-server-optional-debug-rpms" and "sudo subscription-manager repos --enable rhel-7-server-optional-source-rpms

and then you are finaly ready to install
```shell script
sudo yum install devtoolset-11
sudo yum install httpd-devel
sudo yum install openssl-devel libcurl-devel.x86_64
```

to make cmake happy, make sure there exists an apxs2. If it does not, execute the following:
```shell script
sudo cp /usr/bin/apxs /usr/sbin/apxs2
```

### Build sources

If you installed the devtoolset, make sure you enable it for the following by executing
```shell script
sudo scl enable devtoolset-11 'bash'
```

change to the source directory (.../mod_authg_jwt) and create the build folder:
```shell script
mkdir build && cd build
```

Now compile:
If you are on the devtoolset compile like this:
```shell script
export CC=/opt/rh/devtoolset-11/root/usr/bin/gcc 
export CXX=/opt/rh/devtoolset-11/root/usr/bin/g++
cmake .. && make mod_authg_jwt
```
if you are on the standard gcc you may simpliy use:
```shell script
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
