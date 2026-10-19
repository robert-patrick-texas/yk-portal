# Builds yk-portal's Debian package in a disposable Ubuntu 26.04 container
# (docs/deployment.md, "Building the package"), into dist/:
#
#   docker build -f packaging/deb/Dockerfile --output dist .
#
# The release workflow (.github/workflows/release.yml) runs packaging/deb/build
# the same way, in an ubuntu:26.04 container.

FROM ubuntu:26.04 AS build

ARG UV_VERSION=0.13.1
ARG DEB_REVISION=1

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3 python3-dev build-essential libpq-dev ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN curl -LsSf "https://astral.sh/uv/${UV_VERSION}/install.sh" \
    | env UV_INSTALL_DIR=/usr/local/bin UV_NO_MODIFY_PATH=1 sh

COPY . /usr/local/src/yk-portal
RUN DEB_REVISION=$DEB_REVISION /usr/local/src/yk-portal/packaging/deb/build /dist

FROM scratch
COPY --from=build /dist/ /
