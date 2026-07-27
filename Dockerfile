FROM python:3.12-slim AS sasquatch-builder

# Sasquatch: https://github.com/devttys0/sasquatch
# Pinned revision bd864a1b037bf57ca7d64a292a60ba0d6459611f (GPL-2.0-only).
# Build: git checkout <commit> && make. The final stage receives only its binary.
ARG SASQUATCH_COMMIT=bd864a1b037bf57ca7d64a292a60ba0d6459611f
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git liblzma-dev liblzo2-dev wget zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/devttys0/sasquatch.git /src/sasquatch \
    && cd /src/sasquatch \
    && git checkout --detach "$SASQUATCH_COMMIT" \
    && test "$(git rev-parse HEAD)" = "$SASQUATCH_COMMIT" \
    && wget -q https://downloads.sourceforge.net/project/squashfs/squashfs/squashfs4.3/squashfs4.3.tar.gz \
    && tar -zxf squashfs4.3.tar.gz \
    && cd squashfs4.3 \
    && patch -p0 < ../patches/patch0.txt \
    && sed -i 's/-Wall -Werror/-Wall -fcommon/' squashfs-tools/Makefile \
    && cd squashfs-tools \
    && make \
    && make install

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        binwalk \
        squashfs-tools \
        p7zip-full \
        unzip \
        file \
        gzip \
        xz-utils \
        cpio \
        lz4 \
        git \
        build-essential \
        liblzma5 \
        zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY --from=sasquatch-builder /usr/local/bin/sasquatch /usr/local/bin/sasquatch
# Sasquatch prints its version/help text with status 1; verify the installed executable.
RUN sasquatch -version || test -x /usr/local/bin/sasquatch

COPY pyproject.toml README.md /app/
COPY app /app/app
COPY scripts /app/scripts

RUN pip install --no-cache-dir uv && uv pip install --system -e .

WORKDIR /workspace
CMD ["python", "/app/scripts/scan_sample_firmware.py", "--input-dir", "/workspace/sample_data", "--output-dir", "/workspace/output/sample-scans", "--work-dir", "/work"]
