FROM debian:buster-slim AS wget_build
COPY . /tmp/wget
ARG TLSTYPE=openssl
RUN set -eux \
 && case "${TLSTYPE}" in openssl) SSLPKG=libssl-dev;; gnutls) SSLPKG=gnutls-dev;; *) echo "Unknown TLSTYPE ${TLSTYPE}"; exit 1;; esac \
 && echo deb http://deb.debian.org/debian buster-backports main contrib > /etc/apt/sources.list.d/backports.list \
 && DEBIAN_FRONTEND=noninteractive DEBIAN_PRIORITY=critical apt-get -qqy --no-install-recommends -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-unsafe-io update \
 && DEBIAN_FRONTEND=noninteractive DEBIAN_PRIORITY=critical apt-get -qqy --no-install-recommends -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-unsafe-io install "${SSLPKG}" build-essential git bzip2 bash rsync gcc zlib1g-dev autoconf autoconf-archive flex make automake gettext libidn11 autopoint texinfo gperf ca-certificates wget pkg-config libpsl-dev libidn2-dev lua5.1-dev libgpgme-dev  \
 && DEBIAN_FRONTEND=noninteractive DEBIAN_PRIORITY=critical apt-get -qqy --no-install-recommends -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-unsafe-io -t buster-backports install libzstd-dev zstd \
 && cd /tmp/wget \
 && ./bootstrap \
 && ./configure --with-ssl="${TLSTYPE}" -disable-nls \
 && make -j $(nproc) \
 && src/wget -V | grep -q lua
FROM scratch
COPY --from=wget_build /tmp/wget/src/wget /wget
