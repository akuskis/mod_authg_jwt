FROM gcc:latest

RUN apt-get update \
    && apt-get install -y apache2-dev libcurl4-openssl-dev

RUN wget https://github.com/Kitware/CMake/releases/download/v3.19.2/cmake-3.19.2-Linux-x86_64.sh \
    -O /tmp/cmake-install.sh \
    && chmod u+x /tmp/cmake-install.sh \
    && mkdir /usr/bin/cmake \
    && /tmp/cmake-install.sh --skip-license --prefix=/usr/local \
    && rm /tmp/cmake-install.sh

COPY . /app
WORKDIR /app/build

RUN cmake .. -DCMAKE_BUILD_TYPE=Release \
    && make mod_authg_jwt \
    && strip src/libmod_authg_jwt.so
