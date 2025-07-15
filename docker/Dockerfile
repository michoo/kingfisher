# syntax=docker/dockerfile:1
FROM alpine:latest

RUN apk add --no-cache curl tar

ARG TARGETARCH               # set automatically by BuildKit
ENV TARGETARCH=${TARGETARCH}

WORKDIR /app

RUN set -eux; \
    # choose the right asset for this build platform
    case "${TARGETARCH}" in \
        amd64) SUFFIX="linux-x64.tgz"  ;; \
        arm64) SUFFIX="linux-arm64.tgz" ;; \
        *)     echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    # download & unpack
    LATEST_URL=$(curl -s https://api.github.com/repos/mongodb/kingfisher/releases/latest \
        | grep -Eo "https://[^\"]*${SUFFIX}"); \
    curl -L "$LATEST_URL" -o kingfisher.tgz; \
    tar -xzf kingfisher.tgz; \
    rm kingfisher.tgz; \
    # locate the binary (pattern covers kingfisher-linux-x64 / kingfisher-linux-arm64)
    KF_PATH=$(find . -type f -name 'kingfisher*' | head -n1); \
    install -m 0755 "$KF_PATH" /usr/local/bin/kingfisher; \
    # optional cleanup to keep the image small
    rm -rf /app/*

# quick smoke-test so the build fails early if something’s wrong
RUN kingfisher --version

ENTRYPOINT ["kingfisher"]
