# syntax=docker/dockerfile:latest
ARG UBUNTU_VERSION=jammy
ARG AFLPP_VERSION=4.05c
ARG MUSL_TOOLCHAIN=arm-linux-musleabi-native
ARG GHIDRA_VERSION=10.1.5_PUBLIC
ARG GHIDRA_SHA=17db4ba7d411d11b00d1638f163ab5d61ef38712cd68e462eb8c855ec5cfb5ed
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.5_build/ghidra_10.1.5_PUBLIC_20220726.zip
ARG GHIDRATHON_SHA=18ad5fe7adc940009f15de5219b3de1ffe6b6f571fc1e95318d45f074d21fbcc
ARG GHIDRATHON_URL=https://codeload.github.com/mandiant/Ghidrathon/tar.gz/refs/tags/v1.0.0


################################################################################
# Download and decompress musl toolchain for use in the final SURGEON image    #
################################################################################
FROM alpine:latest as musl-toolchain-downloader
ARG MUSL_TOOLCHAIN

# Download and decompression step because ADD cannot (yet) do both at once
ADD --link https://musl.cc/$MUSL_TOOLCHAIN.tgz /

RUN tar -xf /$MUSL_TOOLCHAIN.tgz


################################################################################
# Create the Python venv for use in the final image                            #
# Using a different target allows us to make use of the Docker build cache for #
# the final venv, avoiding the frequent rebuild of keystone-engine             #
################################################################################
FROM --platform=linux/arm64 ubuntu:$UBUNTU_VERSION as python-builder

# Enable APT package caching
RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

# Install base packages (including arm32 libraries and headers)
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        make \
        cmake \
        python3-minimal \
        python3-pip \
        python3-venv

# Install Python dependencies for all modules into the venv (see wildcard below)
RUN --mount=type=bind,source=src,target=/src \
    --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    python3 -m venv /root/.venv && \
    . /root/.venv/bin/activate && \
    pip3 install -U \
        wheel \
        meson && \
    for req in /src/*/requirements.txt; do \
        pip3 install -r $req; \
    done


################################################################################
# Final SURGEON debugger image                                                 #
################################################################################
FROM ubuntu:$UBUNTU_VERSION as debugger

# Enable APT package caching
RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

# Install base packages
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        python3-minimal \
        binutils \
        gdb-multiarch && \
    if [ "$(uname -m)" = "aarch64" ]; then \
        apt-get install -y --no-install-recommends gdbserver; \
    else \
        apt-get install -y --no-install-recommends qemu-user; \
    fi

# Copy entrypoint in
COPY --link --chmod=0755 docker/debugger-entrypoint.sh /debugger-entrypoint.sh
COPY --link --chmod=0755 docker/trace-entrypoint.sh /trace-entrypoint.sh

# Expose port for the debugger to connect to
EXPOSE 1234

ENTRYPOINT ["/bin/bash", "-c"]
CMD ["/debugger-entrypoint.sh"]


################################################################################
# Final SURGEON runner image                                                   #
################################################################################
FROM --platform=linux/arm64 ubuntu:$UBUNTU_VERSION as runner
ARG MUSL_TOOLCHAIN

# Configure APT and DPKG for multiarch and package caching
RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache && \
    dpkg --add-architecture armhf

# Install base packages (including arm32 libraries and headers)
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        make \
        pkg-config \
        binutils-arm-linux-gnueabihf \
        gcc-arm-linux-gnueabihf \
        python3-minimal \
        python3-pip \
        python3-venv \
        libpython3.10 \
        libpython3-dev:armhf \
        ninja-build

# Add musl toolchain
COPY --from=musl-toolchain-downloader --link /$MUSL_TOOLCHAIN /opt/$MUSL_TOOLCHAIN
ENV PATH=$PATH:/opt/$MUSL_TOOLCHAIN/bin

# Add Python venv => set up in different container for better caching
COPY --from=python-builder --link /root/.venv /root/.venv

COPY --from=aflplusplus/aflplusplus@sha256:18b15d4c9602390139523c6bc528fcc95baf959df014134cacfa6cf889a8fafe --link /usr/local/bin /opt/afl
ENV PATH=$PATH:/opt/afl

# Copy entrypoint in
COPY --link --chmod=0755 docker/runner-entrypoint.sh /runner-entrypoint.sh

ENTRYPOINT ["/bin/bash", "-c"]
CMD ["/runner-entrypoint.sh"]


################################################################################
# Download and decompress ghidra(thon) for use in the final ghidrathon image   #
################################################################################
FROM alpine:latest as ghidra-ghidrathon-downloader
ARG GHIDRA_VERSION
ARG GHIDRA_SHA
ARG GHIDRA_URL
ARG GHIDRATHON_SHA
ARG GHIDRATHON_URL

# Download and decompress ghidra because ADD cannot (yet) do both at once
ADD --link $GHIDRA_URL /ghidra.zip

RUN echo "$GHIDRA_SHA  /ghidra.zip" | sha256sum -c - && \
    unzip /ghidra.zip && \
    mv ghidra_${GHIDRA_VERSION} /ghidra && \
    chmod +x /ghidra/ghidraRun

# Download and decompress ghidrathon because ADD cannot (yet) do both at once
ADD --link $GHIDRATHON_URL /ghidrathon.tar.gz

RUN echo "$GHIDRATHON_SHA  /ghidrathon.tar.gz" | sha256sum -c - && \
    tar -xzf /ghidrathon.tar.gz && \
    mv Ghidrathon* /ghidrathon


################################################################################
# Ghidrathon image                                                             #
################################################################################
FROM ubuntu:$UBUNTU_VERSION as ghidrathon
ARG GHIDRA_VERSION

# Enable APT package caching
RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

# Install prerequisites
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        vim \
        wget \
        unzip \
        build-essential \
        libssl-dev \
        libffi-dev \
        python3-dev \
        python3-requests  \
        python3-ipdb \
        python3-ipython \
        python3-pip \
        python-is-python3 \
        openjdk-18-jdk-headless \
        apt-transport-https \
        software-properties-common \
        gpg-agent \
        dirmngr && \
    add-apt-repository -y ppa:cwchien/gradle && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        gradle

# Install Python dependencies
RUN --mount=type=bind,source=src/ghidrathon/requirements.txt,target=/requirements.txt \
    --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    pip3 install -r /requirements.txt

# Add ghidra
COPY --from=ghidra-ghidrathon-downloader --link /ghidra /ghidra

# Build ghidrathon
RUN --mount=type=bind,from=ghidra-ghidrathon-downloader,source=/ghidrathon,target=/ghidrathon,readwrite \
    cd /ghidrathon && \
    gradle -PGHIDRA_INSTALL_DIR=/ghidra && \
    (/ghidra/support/analyzeHeadless --help || mkdir -p ~/.ghidra/.ghidra_${GHIDRA_VERSION}/Extensions) && \
    cd ~/.ghidra/.ghidra_${GHIDRA_VERSION}/Extensions && \
    unzip /ghidrathon/dist/ghidra_${GHIDRA_VERSION}_*_ghidrathon.zip

# Copy entrypoint in
COPY --link --chmod=0755 docker/ghidrathon-entrypoint.sh /ghidrathon-entrypoint.sh

ENTRYPOINT ["/bin/bash", "-c"]
CMD ["/ghidrathon-entrypoint.sh"]
