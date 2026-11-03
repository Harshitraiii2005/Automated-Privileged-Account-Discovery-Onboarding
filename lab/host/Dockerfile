# Lab Linux host (Debian, Ubuntu or AlmaLinux via BASE): sshd + sudo. Local accounts are converged
# at start-up from the generated seed mounted at /seed (see provision.sh).
ARG BASE=debian:trixie-slim
FROM ${BASE}
RUN if command -v apt-get >/dev/null; then \
        apt-get update \
        && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server sudo \
        && rm -rf /var/lib/apt/lists/*; \
    else \
        dnf install -y openssh-server sudo shadow-utils && dnf clean all; \
    fi \
    # Only the pinned host key from /seed is offered, so clients can do strict host-key checking.
    && sed -i '/^HostKey/d' /etc/ssh/sshd_config \
    # Containers lack CAP_AUDIT_CONTROL; a "required" pam_loginuid would reject every SSH session.
    && sed -i 's/^session\s\+required\s\+pam_loginuid\.so/session optional pam_loginuid.so/' /etc/pam.d/sshd \
    && mkdir -p /run/sshd
COPY sshd.conf /etc/ssh/sshd_config.d/10-autoonboard.conf
COPY --chmod=755 provision.sh /usr/local/sbin/provision.sh
# Root-owned and not writable by the tooling accounts that may sudo them.
COPY --chmod=755 autoonboard-collect autoonboard-setpw /usr/local/sbin/
EXPOSE 22
ENTRYPOINT ["/usr/local/sbin/provision.sh"]
