# The environment `cargo xtask reproducible build` builds release artifacts
# in (#74). Everything that reaches an image is pinned: the base by digest,
# the compiler, its components and both targets by `rust-toolchain.toml`,
# which the build copies in from the commit it builds, and `espflash`, which
# makes the comms image, by release and digest. The dependencies are pinned
# by the lockfiles in the staged tree. Moving a pin here is moving what a
# release is built with: the next artifacts will not match the last ones.
FROM rust@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e

# Set by BuildKit to the platform the image is built for.
ARG TARGETARCH

COPY rust-toolchain.toml /toolchain/rust-toolchain.toml
RUN cd /toolchain && rustup toolchain install && rustup show active-toolchain

# The release asset CI measures with on x86-64, and its aarch64 build.
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) asset=espflash-x86_64-unknown-linux-musl.zip; \
             sum=542c5cc81f0cca384cbead1cacb7ccc9f35072a989b2de0fb95333d814272c22 ;; \
      arm64) asset=espflash-aarch64-unknown-linux-gnu.zip; \
             sum=2d5972b9c18fc89bf253e60fe6df6a4f8db3aee5db0166b2c97b53bd21c01f09 ;; \
      *) echo "no pinned espflash for $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -sSfL -o /tmp/espflash.zip "https://github.com/esp-rs/espflash/releases/download/v4.5.0/$asset"; \
    echo "$sum  /tmp/espflash.zip" | sha256sum -c -; \
    unzip -q /tmp/espflash.zip -d /usr/local/bin; \
    chmod 755 /usr/local/bin/espflash; \
    rm /tmp/espflash.zip; \
    espflash --version

# The build runs as the caller's user, which the image has no entry for.
RUN chmod -R a+rwX /usr/local/rustup
