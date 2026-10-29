#!/bin/sh
# Static contract check for the optional ferrogate-mia-tray-admin Debian package
# (feature F22). Inspects the archive without installing it. The administrator
# client runs as the logged-in user and the tray offers it only from a root-owned,
# non-user-writable location, so the package must install exactly one such
# binary and nothing that elevates, autostarts or changes accounts.
set -eu

deb=${1:?usage: check-tray-admin-package.sh path/to/ferrogate-mia-tray-admin.deb}
if [ ! -f "$deb" ]; then
    echo "ERROR: Debian package not found: $deb" >&2
    exit 1
fi

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
dpkg-deb --control "$deb" "$work_dir/control"
dpkg-deb --fsys-tarfile "$deb" | tar -tvf - >"$work_dir/listing"

fail() {
    echo "ERROR: $deb: $1" >&2
    exit 1
}

[ "$(dpkg-deb --field "$deb" Package)" = ferrogate-mia-tray-admin ] || fail "unexpected Debian package name"

# The binary: a regular file, mode 0755, owned by root, beside mia-tray.
entry=$(awk '$NF == "./usr/bin/mia-tray-admin"' "$work_dir/listing")
[ -n "$entry" ] || fail "does not contain /usr/bin/mia-tray-admin"
mode=$(printf '%s\n' "$entry" | awk '{ print $1 }')
owner=$(printf '%s\n' "$entry" | awk '{ print $2 }')
[ "$mode" = "-rwxr-xr-x" ] || fail "/usr/bin/mia-tray-admin has mode $mode, expected -rwxr-xr-x"
[ "$owner" = "root/root" ] || fail "/usr/bin/mia-tray-admin is owned by $owner, expected root/root"

# Nothing setuid or setgid, anywhere.
if awk '{ if ($1 ~ /^[-d]/ && $1 ~ /[sS]/) found = 1 } END { exit !found }' "$work_dir/listing"; then
    fail "contains a setuid or setgid entry"
fi

# Nothing that autostarts, runs as a service, adds a polkit action or a launcher.
for forbidden in etc/xdg/autostart usr/lib/systemd usr/share/polkit-1 usr/share/applications Library/LaunchAgents; do
    if grep -F "./$forbidden" "$work_dir/listing" >/dev/null; then
        fail "ships files under $forbidden"
    fi
done

# Depends on the tray package (ferrogate-mia provides it); needs no account setup.
dpkg-deb --field "$deb" Depends | grep -F 'ferrogate-mia-tray' >/dev/null || fail "missing dependency ferrogate-mia-tray"
for script in preinst postinst prerm postrm; do
    [ -f "$work_dir/control/$script" ] || continue
    sh -n "$work_dir/control/$script"
    if grep -E 'usermod|groupadd|useradd|adduser|gpasswd|polkit|systemctl|sudoers' "$work_dir/control/$script" >/dev/null; then
        fail "maintainer script $script changes accounts, services or privileges"
    fi
done

echo "OK: $deb installs only an unprivileged, root-owned /usr/bin/mia-tray-admin"
