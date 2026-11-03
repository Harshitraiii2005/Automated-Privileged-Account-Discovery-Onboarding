#!/bin/sh
# Converge this lab host's local accounts from the generated seed in /seed, then run sshd.
# Idempotent across restarts: an account's password and password-change date are set only when the
# account is first created, so rotations done later (by the AutoOnboard CPM) survive a restart.
set -eu
S=/seed
rm -f /run/provisioned

install -m 600 "$S/ssh_host_ed25519_key" /etc/ssh/ssh_host_ed25519_key

while IFS='|' read -r name uid shell groups password lastchg expire gecos; do
    case "$name" in '' | '#'*) continue ;; esac
    if ! getent passwd "$name" >/dev/null; then
        if [ "$uid" = 0 ]; then
            useradd -o -u 0 -g 0 -M -d /root -s "$shell" -c "$gecos" "$name"
        else
            useradd -m -u "$uid" -s "$shell" -c "$gecos" "$name"
        fi
        if [ "$password" != none ]; then
            # Random and never recorded anywhere: the account is "unmanaged" until onboarded.
            echo "$name:$(head -c 24 /dev/urandom | base64)" | chpasswd
        fi
        [ -z "$lastchg" ] || chage -d "$lastchg" "$name"
        [ "$password" != locked ] || usermod -L "$name"
    fi
    for g in $(echo "$groups" | tr ',' ' '); do
        getent group "$g" >/dev/null || groupadd "$g"
        usermod -aG "$g" "$name"
    done
    [ -z "$expire" ] || chage -E "$expire" "$name"
done <"$S/accounts.psv"

for f in "$S"/keys/*; do
    [ -e "$f" ] || continue
    user=$(basename "$f")
    home=$(getent passwd "$user" | cut -d: -f6)
    group=$(id -gn "$user")
    install -d -m 700 -o "$user" -g "$group" "$home/.ssh"
    install -m 600 -o "$user" -g "$group" "$f" "$home/.ssh/authorized_keys"
done

# Validate before activating: a broken sudoers file would lock everyone out of sudo.
# (sudo silently ignores sudoers.d files whose names contain a dot, hence the temp name.)
install -m 440 "$S/sudoers" /etc/sudoers.d/.autoonboard.new
visudo -cqf /etc/sudoers.d/.autoonboard.new
mv /etc/sudoers.d/.autoonboard.new /etc/sudoers.d/90-autoonboard

touch /run/provisioned
exec /usr/sbin/sshd -D -e
