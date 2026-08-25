# The caller must supply an immutable base image that already contains Python
# and strace, for example: --build-arg BASE_IMAGE=registry/image@sha256:<digest>.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

WORKDIR /opt/clawlock
COPY clawlock /opt/clawlock/clawlock
ENV CLAWLOCK_ANALYZER_CONTAINER=1

# The outer ClawLock runner supplies the target argv after `--`.  The image is
# intentionally dependency-free and is always run with a read-only rootfs,
# dropped capabilities, no-new-privileges and (by default) no network.
ENTRYPOINT ["python", "-m", "clawlock.sandbox_analyzer"]
