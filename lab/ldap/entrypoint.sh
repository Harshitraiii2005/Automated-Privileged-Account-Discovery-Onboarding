#!/bin/sh
# First boot builds cn=config and bulk-loads the generated seed with slapadd. Offline loading is
# deliberate: it is the only way to backdate operational attributes (createTimestamp, pwdChangedTime,
# pwdLastSuccess), which is what makes stale and never-rotated accounts realistic. Later boots just
# start slapd, so state written by Vault (rotated passwords) survives restarts.
set -eu
: "${LDAP_ADMIN_PASSWORD:?LDAP_ADMIN_PASSWORD must be set (see .env)}"

install -d -o openldap -g openldap -m 750 /etc/ldap/tls /run/slapd
install -o openldap -g openldap -m 644 /seed/ca.crt /seed/ldap.crt /etc/ldap/tls/
install -o openldap -g openldap -m 600 /seed/ldap.key /etc/ldap/tls/

# cn=config.ldif is the "initialised" marker, so it is committed last: a failed first boot retries cleanly.
if [ ! -e /etc/ldap/slapd.d/cn=config.ldif ]; then
    echo "first boot: creating cn=config and loading seed"
    staging=$(mktemp -d)
    rm -rf /var/lib/ldap/* /etc/ldap/slapd.d/*
    rootpw=$(slappasswd -o module-path=/usr/lib/ldap -o module-load=argon2 -h '{ARGON2}' -s "$LDAP_ADMIN_PASSWORD")
    sed "s|@ROOTPW@|$rootpw|" /usr/local/share/autoonboard/slapd-config.ldif | slapadd -q -n0 -F "$staging"
    slapadd -q -n1 -F "$staging" -l /seed/seed.ldif
    chown -R openldap:openldap "$staging" /var/lib/ldap
    cp -a "$staging"/cn=config "$staging"/cn=config.ldif /etc/ldap/slapd.d/
    rm -rf "$staging"
fi
# No plaintext listener at all: LDAPS for clients, ldapi (unix socket, root via SASL EXTERNAL) for local admin.
exec slapd -d stats -u openldap -g openldap -F /etc/ldap/slapd.d -h "ldaps:/// ldapi:///"
