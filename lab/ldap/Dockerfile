# Lab directory: OpenLDAP 2.6 with ppolicy (password age, lockout, disable), lastbind (last logon)
# and argon2 password hashing. Config and data are created on first boot by entrypoint.sh.
FROM debian:trixie-slim
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends slapd ldap-utils \
    && rm -rf /var/lib/apt/lists/* /etc/ldap/slapd.d/* /var/lib/ldap/*
COPY slapd-config.ldif /usr/local/share/autoonboard/slapd-config.ldif
COPY --chmod=755 entrypoint.sh /usr/local/sbin/entrypoint.sh
EXPOSE 636
ENTRYPOINT ["/usr/local/sbin/entrypoint.sh"]
