# The yk-portal lab: yk-portal installed as the deployment guide installs it, in
# a container the host's reverse proxy reaches (lab/README.md).
#
#   docker build -f lab/Dockerfile -t yk-portal-lab .
#   docker build -f lab/Dockerfile --build-arg INSTALL_OPTIONS=--postgresql-c -t yk-portal-lab:pg .
#
# lab/lab builds and runs it; nothing here is for production.

FROM ubuntu:26.04

ARG UV_VERSION=0.13.1
ARG INSTALL_OPTIONS=""

# The deployment guide's prerequisites; the build tools only for --postgresql-c.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3 libpq5 ca-certificates curl sqlite3 tini \
    && if [ -n "$INSTALL_OPTIONS" ]; then \
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            build-essential python3-dev libpq-dev; \
    fi \
    && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf "https://astral.sh/uv/${UV_VERSION}/install.sh" \
    | env UV_INSTALL_DIR=/usr/local/bin UV_NO_MODIFY_PATH=1 sh

COPY . /usr/local/src/yk-portal
RUN /usr/local/src/yk-portal/deploy/install --no-systemd $INSTALL_OPTIONS \
    && rm -rf /root/.cache/uv

EXPOSE 8000
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/src/yk-portal/lab/entrypoint"]
