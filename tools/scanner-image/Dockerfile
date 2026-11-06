# syntax=docker/dockerfile:1
# Scanner image ujc-scanner - static scanners and tools for the behavior probe.
# Build:  tools/setup.sh (step "image") or
#         docker build -t ujc-scanner:<YYYY-MM-DD> tools/scanner-image
# Principles:
#  - base pinned by digest; every tool at a fixed version
#  - binaries from the official GitHub releases, SHA-256 fixed here and compared with the
#    vendor's checksum file (as of 2026-10-10)
#  - Python tools each in their own venv from lock files with hashes (--require-hashes, wheels only)
#  - npm tools from package-lock.json with integrity hashes, without install scripts
#  - no token, no secret in the image (scorecard/snyk-agent-scan get their tokens at runtime)
# Versions and self-download behaviour: README.md and VERSIONS.md in this folder.

ARG BASE=python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258

# ---------------------------------------------------------------- fetch and verify binaries
FROM ${BASE} AS fetch
# Tools only for downloading in this intermediate stage; they do not end up in the image, and
# everything they fetch is verified by SHA-256 or commit hash - hence no version pin here
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl xz-utils git \
 && rm -rf /var/lib/apt/lists/*
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
WORKDIR /dl
RUN mkdir -p /out/bin
# fetch <url> <file> <sha256> - aborts on a wrong checksum ($1..$3 are intentional)
# hadolint ignore=SC2016
RUN printf '%s\n' '#!/bin/sh' 'set -eu' \
      'curl -fsSL --retry 3 --proto =https -o "$2" "$1"' \
      'echo "$3  $2" | sha256sum -c -' > /usr/local/bin/fetch \
 && chmod +x /usr/local/bin/fetch

ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
RUN fetch https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz gitleaks.tgz ${GITLEAKS_SHA256} \
 && tar -xzf gitleaks.tgz gitleaks && install -m 0755 gitleaks /out/bin/gitleaks
# Default gitleaks rules as a file: scan.sh passes them with --config so that a
# .gitleaks.toml in the target cannot replace the rules
ARG GITLEAKS_CONFIG_SHA256=e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf
RUN mkdir -p /out/ujc \
 && fetch https://raw.githubusercontent.com/gitleaks/gitleaks/v${GITLEAKS_VERSION}/config/gitleaks.toml /out/ujc/gitleaks.toml ${GITLEAKS_CONFIG_SHA256}

ARG TRUFFLEHOG_VERSION=3.99.2
ARG TRUFFLEHOG_SHA256=3c7b0d1dc4278294269bfdd7594bca8bb28c78da0a4a06ad202ded37b48deca4
RUN fetch https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz trufflehog.tgz ${TRUFFLEHOG_SHA256} \
 && tar -xzf trufflehog.tgz trufflehog && install -m 0755 trufflehog /out/bin/trufflehog

ARG OSV_VERSION=2.6.0
ARG OSV_SHA256=ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108
RUN fetch https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_amd64 osv-scanner ${OSV_SHA256} \
 && install -m 0755 osv-scanner /out/bin/osv-scanner

ARG TRIVY_VERSION=0.75.0
ARG TRIVY_SHA256=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f
RUN fetch https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz trivy.tgz ${TRIVY_SHA256} \
 && tar -xzf trivy.tgz trivy && install -m 0755 trivy /out/bin/trivy

ARG SYFT_VERSION=1.54.1
ARG SYFT_SHA256=c069905b391cc4c20a5ba65ad5c10be2a7ba074f8ea6ad203e24d14e303dad47
RUN fetch https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz syft.tgz ${SYFT_SHA256} \
 && tar -xzf syft.tgz syft && install -m 0755 syft /out/bin/syft

ARG GRYPE_VERSION=0.120.1
ARG GRYPE_SHA256=0a9ee97ef5ae2ee953b0a80098105052e846cdbe319a57d808b519c33cd1343d
RUN fetch https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz grype.tgz ${GRYPE_SHA256} \
 && tar -xzf grype.tgz grype && install -m 0755 grype /out/bin/grype

ARG ACTIONLINT_VERSION=1.7.12
ARG ACTIONLINT_SHA256=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
RUN fetch https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz actionlint.tgz ${ACTIONLINT_SHA256} \
 && tar -xzf actionlint.tgz actionlint && install -m 0755 actionlint /out/bin/actionlint

ARG HADOLINT_VERSION=2.15.1
ARG HADOLINT_SHA256=c7187db94eeeeca956519a6af171adc31453941a1e777961f6e680f697c8c507
RUN fetch https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-linux-x86_64 hadolint ${HADOLINT_SHA256} \
 && install -m 0755 hadolint /out/bin/hadolint

# ShellCheck publishes no checksum file; the SHA-256 was compared with the asset digest of the
# GitHub release API (2026-10-10)
ARG SHELLCHECK_VERSION=0.11.0
ARG SHELLCHECK_SHA256=8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198
RUN fetch https://github.com/koalaman/shellcheck/releases/download/v${SHELLCHECK_VERSION}/shellcheck-v${SHELLCHECK_VERSION}.linux.x86_64.tar.xz shellcheck.txz ${SHELLCHECK_SHA256} \
 && tar -xJf shellcheck.txz shellcheck-v${SHELLCHECK_VERSION}/shellcheck \
 && install -m 0755 shellcheck-v${SHELLCHECK_VERSION}/shellcheck /out/bin/shellcheck

ARG SCORECARD_VERSION=5.5.0
ARG SCORECARD_SHA256=83b90a05c1540ef1390db1cd5711e5fd04be9c1d8537fb84d39d02092d6a8dff
RUN fetch https://github.com/ossf/scorecard/releases/download/v${SCORECARD_VERSION}/scorecard_${SCORECARD_VERSION}_linux_amd64.tar.gz scorecard.tgz ${SCORECARD_SHA256} \
 && mkdir sc && tar -xzf scorecard.tgz -C sc \
 && install -m 0755 "$(find sc -type f -name 'scorecard*' -perm -u+x | head -n 1)" /out/bin/scorecard

# Node.js (official tarball, checksum from SHASUMS256.txt on nodejs.org)
ARG NODE_VERSION=24.21.0
ARG NODE_SHA256=fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6
RUN fetch https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz node.txz ${NODE_SHA256} \
 && mkdir -p /out/node && tar -xJf node.txz -C /out/node --strip-components=1 \
 && rm -rf /out/node/include /out/node/share/doc /out/node/share/man

# Semgrep rules locally (fixed commit, integrity via the commit hash) - so semgrep runs
# without registry and without network
ARG SEMGREP_RULES_COMMIT=9bbf021d0acffa3095fcffd17b2bc7787eb4796d
RUN git init -q /out/semgrep-rules \
 && git -C /out/semgrep-rules fetch -q --depth 1 https://github.com/semgrep/semgrep-rules.git ${SEMGREP_RULES_COMMIT} \
 && git -C /out/semgrep-rules -c advice.detachedHead=false checkout -q FETCH_HEAD \
 && test "$(git -C /out/semgrep-rules rev-parse HEAD)" = "${SEMGREP_RULES_COMMIT}" \
 && echo "${SEMGREP_RULES_COMMIT}" > /out/semgrep-rules/UJC-COMMIT \
 && rm -rf /out/semgrep-rules/.git /out/semgrep-rules/.github /out/semgrep-rules/stats /out/semgrep-rules/scripts \
 && find /out/semgrep-rules \( -name '*.test.*' -o -name '*.fixed.*' -o -name '.pre-commit*' \) -delete \
 && find /out/semgrep-rules -maxdepth 1 -type f ! -name LICENSE ! -name README.md ! -name UJC-COMMIT -delete

# ---------------------------------------------------------------- Python tools (venvs)
FROM ${BASE} AS py
COPY lock/ /lock/
RUN set -eux; for n in pytools semgrep guarddog agent-scan; do \
      python -m venv /opt/venv/$n; \
      /opt/venv/$n/bin/pip install -q --disable-pip-version-check --no-cache-dir \
        --no-deps --require-hashes --only-binary=:all: -r /lock/$n.txt; \
    done

# ---------------------------------------------------------------- npm tools
FROM ${BASE} AS npm
COPY --from=fetch /out/node /opt/node
ENV PATH=/opt/node/bin:$PATH
WORKDIR /opt/npm-tools
COPY npm/package.json npm/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund --omit=dev \
 && npm cache clean --force

# ---------------------------------------------------------------- final stage
FROM ${BASE}
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG IMAGE_DATE=unknown
# Hash over the build context (setup.sh) - tells whether the image matches the repository state
ARG UJC_CONTEXT=unknown
LABEL ujc.context="${UJC_CONTEXT}" \
      org.opencontainers.image.title="ujc-scanner" \
      org.opencontainers.image.description="Scanner image of the ujc-security-checker: static scanners and tools for the behavior probe" \
      org.opencontainers.image.created="${IMAGE_DATE}" \
      ujc.sandbox="1"
# git: for gitleaks in Git mode; strace/tcpdump/inotify-tools: behavior probe.
# Fixed Debian versions (bookworm, as of 2026-10-10). If the build breaks because Debian replaced a
# version with a security update: enter the new version (apt-cache policy), do not unpin.
ARG APT_PACKAGES="ca-certificates=20250419~deb12u1 git=1:2.39.5-0+deb12u3 strace=6.1-0.1 tcpdump=4.99.3-1 inotify-tools=3.22.6.0-4 procps=2:4.0.2-3"
# Versions are in APT_PACKAGES (hadolint does not see them there); word splitting is intended
# hadolint ignore=DL3008,SC2046,SC2086
RUN apt-get update \
 && apt-get install -y --no-install-recommends ${APT_PACKAGES} \
 && rm -rf /var/lib/apt/lists/* \
 && dpkg-query -W -f='${Package}=${Version}\n' $(echo ${APT_PACKAGES} | sed 's/=[^ ]*//g') > /opt/ujc-apt-versions.txt
COPY --from=fetch /out/bin/ /usr/local/bin/
COPY --from=fetch /out/node /opt/node
COPY --from=fetch /out/semgrep-rules /opt/semgrep-rules
COPY --from=py /opt/venv /opt/venv
COPY --from=npm /opt/npm-tools /opt/npm-tools
COPY --from=fetch /out/ujc/gitleaks.toml /opt/ujc/gitleaks.toml
COPY scan_inside.sh /opt/ujc/scan_inside.sh
RUN set -eux; \
    chmod 0755 /opt/ujc/scan_inside.sh; \
    for t in bandit zizmor ruff radon lizard; do ln -s /opt/venv/pytools/bin/$t /usr/local/bin/$t; done; \
    for t in semgrep pysemgrep; do ln -s /opt/venv/semgrep/bin/$t /usr/local/bin/$t; done; \
    ln -s /opt/venv/guarddog/bin/guarddog /usr/local/bin/guarddog; \
    for t in /opt/venv/agent-scan/bin/*agent-scan* /opt/venv/agent-scan/bin/mcp-scan; do \
      [ -e "$t" ] && ln -s "$t" /usr/local/bin/"$(basename "$t")" || true; done; \
    for t in node npm npx; do ln -s /opt/node/bin/$t /usr/local/bin/$t; done; \
    for t in jscpd knip; do ln -s /opt/npm-tools/node_modules/.bin/$t /usr/local/bin/$t; done; \
    useradd -m -u 10001 -s /bin/bash scanner; \
    install -d -o 10001 -g 10001 /db
# telemetry and self-update checks off (notes per tool in the README)
ENV SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    GRYPE_CHECK_FOR_APP_UPDATE=false \
    SYFT_CHECK_FOR_APP_UPDATE=false \
    TRIVY_DISABLE_VEX_NOTICE=true \
    TRIVY_DISABLE_TELEMETRY=true \
    TRIVY_SKIP_VERSION_CHECK=true \
    ZIZMOR_OFFLINE=true \
    DO_NOT_TRACK=1 \
    NO_UPDATE_NOTIFIER=1 \
    npm_config_update_notifier=false \
    PATH=/usr/local/bin:/opt/node/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
USER 10001:10001
WORKDIR /home/scanner
CMD ["bash"]
