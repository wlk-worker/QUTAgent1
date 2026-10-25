# syntax=docker/dockerfile:1
# QUTAgent competition image: Web / Pwn / AI-security toolchain.
#
# Build (linux/amd64):
#   docker build --pull=false --platform linux/amd64 -t qutagent:dev .
#
# Everything is installed at build time. The evaluation run must not need
# network access or package installation; see docs/toolchain.md for the
# inventory, actual versions and the deliberately omitted tools.
FROM --platform=linux/amd64 python:3.11-slim

ARG DEBIAN_FRONTEND=noninteractive
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TERM=dumb \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PLAYWRIGHT_BROWSERS_PATH=/opt/playwright \
    NUCLEI_TEMPLATES=/opt/nuclei-templates \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# ---- 1. System packages (required; a failure here fails the build) ----------
# Debian 13 ships xxd as its own package (it is no longer part of vim-common).
# ruby/ruby-dev: one_gadget and seccomp-tools are Ruby gems.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates openssl \
        curl wget jq file xxd bsdextrautils \
        unzip zip git patch \
        binutils binutils-multiarch libc6-dev \
        gdb gdbserver libc6-dbg patchelf \
        socat netcat-openbsd \
        nmap sqlmap ffuf gobuster \
        binwalk \
        perl libwhisker2-perl libnet-ssleay-perl libjson-pp-perl libxml-writer-perl \
        strace ltrace procps \
        gcc g++ make pkg-config libffi-dev zlib1g-dev libssl-dev libseccomp-dev \
        ruby ruby-dev \
    && rm -rf /var/lib/apt/lists/* \
    && command -v xxd && command -v readelf && command -v nc

# ---- 2. radare2 -------------------------------------------------------------
# Debian 13 has no radare2 package (only a "none" candidate), so build a pinned
# release from source. `--install` copies real files; without it the script
# symstalls symlinks that point into the build tree and break when it is removed.
RUN git clone --depth 1 --branch 5.9.8 https://github.com/radareorg/radare2.git /tmp/radare2 \
    && cd /tmp/radare2 \
    && sys/install.sh --install \
    && ldconfig \
    && r2 -v \
    && cd / \
    && rm -rf /tmp/radare2 \
    && r2 -v \
    && rabin2 -v \
    && test -x /usr/local/bin/r2

# ---- 3. Ruby tools ----------------------------------------------------------
# one_gadget: libc one-shot gadgets for ret2libc. seccomp-tools: seccomp filter
# dump/disassembly in exploitation. Guarded because they are not in apt.
RUN set -eux; \
    if gem install --no-document one_gadget seccomp-tools; then \
        gem list --local one_gadget seccomp-tools; \
    else \
        echo "WARN: one_gadget/seccomp-tools gem install failed"; \
    fi

# ---- 4. Python Web / Pwn / AI-security libraries ----------------------------
# pwntools (pwn+checksec+asm+ROP), requests/httpx/bs4 (Web), mcp (AI-security
# MCP servers), websocket-client (WebSocket targets), z3/capstone (solving and
# disassembly), ROPGadget, pyelftools. All wheels, no compiler needed.
# setuptools is pinned below 81: newer releases drop pkg_resources, which
# pwntools still uses to populate PLT entries.
RUN python -m pip install --no-cache-dir --upgrade pip wheel "setuptools<81" \
    && python -c "import pkg_resources" \
    && python -m pip install --no-cache-dir \
        pwntools \
        requests \
        httpx \
        beautifulsoup4 \
        lxml \
        websocket-client \
        z3-solver \
        capstone \
        ROPGadget \
        pyelftools \
        mcp

# ---- 5. angr: deliberately omitted -----------------------------------------
# angr is conditional in the requirements ("only if size/build is controllable").
# In this image its dependency graph does not import: pyvex needs the
# bitstring<4.3 API while the resolver installs 4.4+, and angr/pycparser need
# pycparser<3 while the environment already carries pycparser 3.x from the
# pwntools stack. It is reported as an optional gap by check_toolchain; nothing
# in this image may assume angr is present.

# ---- 6. Playwright + Chromium (optional; guarded) --------------------------
# Needed only for JavaScript-rendered Web targets. `--with-deps` installs the
# shared libraries Chromium needs; the plain install is the fallback. Both are
# guarded because browser availability is a size/latency trade-off.
RUN set -eux; \
    if python -m pip install --no-cache-dir playwright; then \
        python -m playwright install --with-deps chromium \
            || python -m playwright install chromium \
            || echo "WARN: chromium download failed"; \
        chmod -R a+rX /opt/playwright 2>/dev/null || true; \
    else \
        echo "WARN: playwright package install failed"; \
    fi

# ---- 7. Standalone binaries (guarded) --------------------------------------
# checksec.sh: standalone `checksec` command in addition to `pwn checksec`.
RUN set -eux; \
    if curl -fsSL https://raw.githubusercontent.com/slimm609/checksec.sh/master/checksec \
            -o /tmp/checksec.sh \
       && install -m 0755 /tmp/checksec.sh /usr/local/bin/checksec \
       && rm -f /tmp/checksec.sh; then \
        echo "checksec.sh installed"; \
    else \
        echo "WARN: checksec.sh unavailable (ctf-checksec uses pwn/readelf)"; \
    fi

# grpcurl: gRPC probing for AI/API targets. Static release binary.
RUN set -eux; \
    if tag=$(curl -fsSL -o /dev/null -w '%{url_effective}' \
            https://github.com/fullstorydev/grpcurl/releases/latest) \
       && ver=${tag##*/tag/v} \
       && curl -fsSL -o /tmp/grpcurl.tar.gz \
            "https://github.com/fullstorydev/grpcurl/releases/download/v${ver}/grpcurl_${ver}_linux_x86_64.tar.gz" \
       && tar -xzf /tmp/grpcurl.tar.gz -C /usr/local/bin grpcurl \
       && chmod 0755 /usr/local/bin/grpcurl \
       && rm -f /tmp/grpcurl.tar.gz \
       && grpcurl --version 2>&1 | head -1; then \
        echo "grpcurl installed"; \
    else \
        echo "WARN: grpcurl unavailable"; \
    fi

# nuclei: template-based Web scanning. The official template corpus is large;
# this image ships a small starter set in /opt/nuclei-templates instead, so the
# tool is usable offline for basic exposure checks (see docs/toolchain.md).
RUN set -eux; \
    if tag=$(curl -fsSL -o /dev/null -w '%{url_effective}' \
            https://github.com/projectdiscovery/nuclei/releases/latest) \
       && ver=${tag##*/tag/v} \
       && curl -fsSL -o /tmp/nuclei.zip \
            "https://github.com/projectdiscovery/nuclei/releases/download/v${ver}/nuclei_${ver}_linux_amd64.zip" \
       && unzip -o -q /tmp/nuclei.zip nuclei -d /usr/local/bin \
       && chmod 0755 /usr/local/bin/nuclei \
       && rm -f /tmp/nuclei.zip \
       && nuclei -version 2>&1 | head -1; then \
        echo "nuclei installed"; \
    else \
        echo "WARN: nuclei unavailable"; \
    fi

# nikto: Perl web scanner, no Debian 13 package. Clone upstream and link it;
# its Perl dependencies were installed in step 1. Guarded.
RUN set -eux; \
    if git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
       && rm -rf /opt/nikto/.git \
       && chmod 0755 /opt/nikto/program/nikto.pl \
       && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
       && perl /opt/nikto/program/nikto.pl -Version >/dev/null 2>&1; then \
        echo "nikto installed"; \
    else \
        echo "WARN: nikto unavailable"; \
        rm -rf /opt/nikto /usr/local/bin/nikto; \
    fi

# ---- 7b. Trim build residue ------------------------------------------------
# Documentation/man pages and package caches are not needed at runtime and only
# inflate the image.
RUN rm -rf /usr/share/doc/* /usr/share/man/* /usr/share/lintian \
        /var/cache/apt/* /var/lib/apt/lists/* \
        /usr/local/lib/ruby/gems/*/cache \
        /tmp/* 2>/dev/null || true

# ---- 8. Runtime user, workspace and entrypoint assets ----------------------
RUN useradd --create-home --uid 10001 agent \
    && mkdir -p /app/scripts /opt/nuclei-templates /ctfy/work \
    && chown agent:agent /ctfy/work

COPY agent /app/agent
COPY toolbox/bin/ /usr/local/bin/
COPY toolbox/toolchain.txt /app/toolchain.txt
COPY toolbox/nuclei-templates/ /opt/nuclei-templates/
COPY scripts/check_toolchain.py /app/scripts/check_toolchain.py

RUN chmod 0755 /usr/local/bin/ctf-checksec /usr/local/bin/ctf-disasm \
        /usr/local/bin/ctf-debug /usr/local/bin/ctf-strings /usr/local/bin/ctf-browse \
    && chmod 0755 /app/scripts/check_toolchain.py \
    && chmod -R a+rX /app/agent /app/toolchain.txt /opt/nuclei-templates \
    && { \
        echo "# QUTAgent toolchain inventory, generated at image build time"; \
        echo "## python"; python --version; \
        echo "## pip packages"; python -m pip list --format=freeze; \
        echo "## dpkg packages"; dpkg-query -W; \
        echo "## ruby gems"; gem list; \
        echo "## tool paths"; \
        for tool in r2 gdb objdump readelf strings nmap sqlmap ffuf gobuster \
                    binwalk patchelf socat nc nikto nuclei grpcurl checksec \
                    one_gadget seccomp-tools ROPgadget ctf-checksec ctf-disasm \
                    ctf-debug ctf-strings ctf-browse; do \
            if path=$(command -v "$tool" 2>/dev/null); then \
                printf '%s: %s\n' "$tool" "$path"; \
            else \
                printf '%s: MISSING\n' "$tool"; \
            fi; \
        done; \
       } > /app/tool-versions.txt \
    && chmod 0644 /app/tool-versions.txt

WORKDIR /ctfy/work
USER agent
ENTRYPOINT ["python", "/app/agent/main.py"]
