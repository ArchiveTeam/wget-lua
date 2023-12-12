FROM debian:bookworm-slim AS wget_build
ARG TLSTYPE=openssl
ENV LC_ALL=C
RUN set -eux \
 && case "${TLSTYPE}" in openssl) SSLPKG=libssl-dev;; gnutls) SSLPKG=gnutls-dev;; *) echo "Unknown TLSTYPE ${TLSTYPE}"; exit 1;; esac \
 && DEBIAN_FRONTEND=noninteractive DEBIAN_PRIORITY=critical apt-get -qqy --no-install-recommends -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-unsafe-io update \
 && DEBIAN_FRONTEND=noninteractive DEBIAN_PRIORITY=critical apt-get -qqy --no-install-recommends -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-unsafe-io upgrade \
 && DEBIAN_FRONTEND=noninteractive DEBIAN_PRIORITY=critical apt-get -qqy --no-install-recommends -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-unsafe-io install "${SSLPKG}" build-essential git bzip2 bash rsync gcc zlib1g-dev autoconf autoconf-archive flex make automake gettext libidn-dev autopoint texinfo gperf ca-certificates wget pkg-config libpsl-dev libidn2-dev libluajit-5.1-dev libgpgme-dev libpcre2-dev
RUN cd /tmp \
 && wget https://github.com/facebook/zstd/releases/download/v1.4.4/zstd-1.4.4.tar.gz \
 && tar xf zstd-1.4.4.tar.gz \
 && cd zstd-1.4.4 \
 && make \
 && make install
RUN cd /tmp \
 && wget https://github.com/c-ares/c-ares/releases/download/cares-1_23_0/c-ares-1.23.0.tar.gz \
 && tar xf c-ares-1.23.0.tar.gz \
 && cd c-ares-1.23.0 \
 && ./configure \
 && make \
 && make install
RUN ldconfig
COPY . /tmp/wget
RUN cd /tmp/wget \
 && ./bootstrap \
 && ./configure --with-ssl="${TLSTYPE}" --with-cares --disable-nls \
 && make -j $(nproc) \
 && src/wget --help | grep -iE "gnu|warc|lua|dns|host|resolv"
FROM scratch
COPY --from=wget_build /tmp/wget/src/wget /wget
COPY --from=wget_build /usr/local/lib /usr/local/lib
