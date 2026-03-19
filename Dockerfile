ARG TLSTYPE=nss
FROM debian:bookworm-slim AS wget_build
ARG TLSTYPE
ENV LC_ALL=C
RUN set -eux \
 && case $TLSTYPE in \
      openssl) SSLPKG='libssl-dev' ;; \
      gnutls) SSLPKG='libgnutls28-dev' ;; \
      nss) SSLPKG='gyp libnspr4-dev libsqlite3-dev nss-plugin-pem ninja-build' ;; \
      *) echo "Unknown TLSTYPE ${TLSTYPE}"; exit 1 ;; \
    esac \
 && DEBIAN_FRONTEND=noninteractive DEBIAN_PRIORITY=critical apt-get -qqy --no-install-recommends -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-unsafe-io update \
 && DEBIAN_FRONTEND=noninteractive DEBIAN_PRIORITY=critical apt-get -qqy --no-install-recommends -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-unsafe-io install ${SSLPKG} build-essential bzip2 bash rsync zlib1g-dev libbrotli-dev autoconf autoconf-archive flex automake gettext libidn-dev autopoint texinfo gperf ca-certificates wget git pkg-config libpsl-dev libidn2-dev libluajit-5.1-dev libgpgme-dev libpcre2-dev
RUN set -eux \
 && cd /tmp \
 && if [ $TLSTYPE = nss ]; then \
      wget https://github.com/nss-dev/nss/archive/refs/tags/NSS_3_121_RTM.tar.gz; \
      echo 'b88d4af0f00186d2542c86cf17a2031f6cca6b9fb31cb64a305589ee1ca4fe8b  NSS_3_121_RTM.tar.gz' | sha256sum --check; \
      tar xf NSS_3_121_RTM.tar.gz; \
      cd nss-NSS_3_121_RTM; \
      ./build.sh -o --disable-tests --system-sqlite --system-nspr; \
      mkdir -p /usr/local/include/nss /usr/local/include/nspr; \
      cp -a ../dist/public/nss/. /usr/local/include/nss/; \
      cp -a /usr/include/nspr/. /usr/local/include/nspr/; \
      rm -f ../dist/Release/lib/*.TOC; \
      cp -a ../dist/Release/lib/* /usr/local/lib/; \
      cp -a /usr/lib/x86_64-linux-gnu/nss/libnsspem.so* /usr/local/lib/; \
      cp -a /lib/x86_64-linux-gnu/libnspr4.so* /usr/local/lib/; \
      cp -a /lib/x86_64-linux-gnu/libplc4.so* /usr/local/lib/; \
      cp -a /lib/x86_64-linux-gnu/libplds4.so* /usr/local/lib/; \
    fi
RUN cd /tmp \
 && wget https://github.com/vapier/ncompress/archive/c576364d691df490ec1841d028c7bece2b523c58.tar.gz -O ncompress.tar.gz \
 && echo '4ffc3de25ac0ba2e76684e0b300502db8bba931de99a8a0d9dc0533d1efd4f2a  ncompress.tar.gz' | sha256sum --check \
 && tar xf ncompress.tar.gz \
 && cd ncompress-c576364d691df490ec1841d028c7bece2b523c58 \
 && echo 'WGET_AT_NCOMPRESS { global: ncompress_compress_fd; ncompress_uncompress_fd; local: *; };' > ncompress.map \
 && gcc -fPIC -shared -Dcompress=ncompress_compress_fd -Ddecompress=ncompress_uncompress_fd -Dstatic= -Wl,--version-script=ncompress.map -o /usr/local/lib/libncompress.so compress.c
RUN cd /tmp \
 && wget https://github.com/facebook/zstd/releases/download/v1.4.4/zstd-1.4.4.tar.gz \
 && echo '59ef70ebb757ffe74a7b3fe9c305e2ba3350021a918d168a046c6300aeea9315  zstd-1.4.4.tar.gz' | sha256sum --check \
 && tar xf zstd-1.4.4.tar.gz \
 && cd zstd-1.4.4 \
 && make \
 && make install
RUN cd /tmp \
 && wget https://github.com/c-ares/c-ares/releases/download/cares-1_23_0/c-ares-1.23.0.tar.gz \
 && echo 'cb614ecf78b477d35963ebffcf486fc9d55cc3d3216f00700e71b7d4868f79f5  c-ares-1.23.0.tar.gz' | sha256sum --check \
 && tar xf c-ares-1.23.0.tar.gz \
 && cd c-ares-1.23.0 \
 && ./configure --disable-tests \
 && make \
 && make install
RUN ldconfig
COPY . /tmp/wget
RUN cd /tmp/wget \
 && case $TLSTYPE in \
      nss) CONFOPT='--with-libnss-prefix=/usr/local' ;; \
      *) CONFOPT= ;; \
    esac \
 && ./bootstrap \
 && ./configure --with-ssl=$TLSTYPE $CONFOPT --with-cares --disable-nls \
 && make -j $(nproc) \
 && src/wget --help | grep -iE "gnu|warc|lua|dns|host|resolv|impersonate"
FROM debian:trixie-slim AS new_certs
ARG TLSTYPE
RUN DEBIAN_FRONTEND=noninteractive DEBIAN_PRIORITY=critical apt-get -qqy --no-install-recommends -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-unsafe-io update \
 && DEBIAN_FRONTEND=noninteractive DEBIAN_PRIORITY=critical apt-get -qqy --no-install-recommends -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-unsafe-io install ca-certificates \
 && mkdir -p /usr/local/etc \
 && if [ $TLSTYPE = nss ]; \
    then \
      echo 'ca_certificate = /etc/ssl/certs/ca-certificates.crt' > /usr/local/etc/wgetrc; \
    else \
      touch /usr/local/etc/wgetrc; \
    fi
FROM scratch
COPY --from=wget_build /tmp/wget/src/wget /wget
COPY --from=wget_build /usr/local/lib /usr/local/lib
COPY --from=new_certs /etc/ssl/certs /etc/ssl/certs
COPY --from=new_certs /usr/local/etc/wgetrc /usr/local/etc/wgetrc
