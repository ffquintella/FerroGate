#!/bin/sh
# Static contract check for the Debian workstation installer. This inspects the
# archive without installing it, so it is safe to run in CI and on dev hosts.
set -eu

deb=${1:?usage: check-deb-package.sh path/to/ferrogate-mia.deb}
if [ ! -f "$deb" ]; then
    echo "ERROR: Debian package not found: $deb" >&2
    exit 1
fi

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
dpkg-deb --control "$deb" "$work_dir/control"
dpkg-deb --fsys-tarfile "$deb" | tar -tf - >"$work_dir/files"

require_file() {
    path=$1
    if ! grep -Fx ".$path" "$work_dir/files" >/dev/null; then
        echo "ERROR: $deb does not contain $path" >&2
        exit 1
    fi
}

[ "$(dpkg-deb --field "$deb" Package)" = ferrogate-mia ] || {
    echo "ERROR: unexpected Debian package name" >&2
    exit 1
}

for path in \
    /usr/bin/mia \
    /usr/bin/mia-tray \
    /etc/xdg/autostart/mia-tray.desktop \
    /usr/lib/systemd/user/mia-tray.service \
    /usr/share/icons/hicolor/scalable/apps/ferrogate-mia.svg \
    /usr/share/icons/hicolor/256x256/apps/ferrogate-mia.png \
    /usr/share/polkit-1/actions/br.fgv.ferrogate.mia.setup.policy; do
    require_file "$path"
done

depends=$(dpkg-deb --field "$deb" Depends)
for dependency in libgtk-3-0 libayatana-appindicator3-1 policykit-1 systemd passwd; do
    printf '%s\n' "$depends" | grep -F "$dependency" >/dev/null || {
        echo "ERROR: missing Debian dependency $dependency" >&2
        exit 1
    }
done

for relation in Conflicts Replaces Provides; do
    dpkg-deb --field "$deb" "$relation" | grep -F 'ferrogate-mia-tray' >/dev/null || {
        echo "ERROR: missing $relation migration for ferrogate-mia-tray" >&2
        exit 1
    }
done

sh -n "$work_dir/control/postinst"
sh -n "$work_dir/control/postrm"
grep -F 'ferrogate-clients' "$work_dir/control/postinst" >/dev/null
grep -F 'ferrogate-status' "$work_dir/control/postinst" >/dev/null
grep -F '_ferrogate' "$work_dir/control/postinst" >/dev/null
grep -F 'systemctl --user restart mia-tray.service' "$work_dir/control/postinst" >/dev/null
if grep -F '#DEBHELPER#' "$work_dir/control/postinst" >/dev/null; then
    echo "ERROR: cargo-deb did not expand #DEBHELPER# in postinst" >&2
    exit 1
fi

echo "OK: $deb contains MIA, tray, autostart, access groups, and lifecycle hooks"
