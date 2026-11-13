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
dpkg-deb -x "$deb" "$work_dir/root"
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
    /usr/share/applications/ferrogate-mia.desktop \
    /usr/lib/systemd/user/mia-tray.service \
    /usr/share/icons/hicolor/scalable/apps/ferrogate-mia.svg \
    /usr/share/icons/hicolor/256x256/apps/ferrogate-mia.png \
    /usr/share/polkit-1/actions/br.fgv.ferrogate.mia.setup.policy \
    /usr/share/polkit-1/rules.d/50-ferrogate-operators.rules \
    /usr/lib/udev/rules.d/70-ferrogate-mia-tpm.rules; do
    require_file "$path"
done

launcher="$work_dir/root/usr/share/applications/ferrogate-mia.desktop"
grep -Fx 'Exec=/usr/bin/mia-tray --window status' "$launcher" >/dev/null || {
    echo "ERROR: FerroGate MIA launcher must open the status window" >&2
    exit 1
}
if grep -Fx 'NoDisplay=true' "$launcher" >/dev/null; then
    echo "ERROR: FerroGate MIA launcher is hidden from application menus" >&2
    exit 1
fi
if command -v desktop-file-validate >/dev/null 2>&1; then
    desktop-file-validate "$launcher"
fi

tpm_rule="$work_dir/root/usr/lib/udev/rules.d/70-ferrogate-mia-tpm.rules"
grep -F 'ACTION=="add|change"' "$tpm_rule" >/dev/null || {
    echo "ERROR: TPM rule must run only when a device is added or changed" >&2
    exit 1
}
grep -F 'SUBSYSTEM=="tpmrm"' "$tpm_rule" >/dev/null || {
    echo "ERROR: TPM rule must match only resource-manager devices" >&2
    exit 1
}
grep -F 'KERNEL=="tpmrm[0-9]*"' "$tpm_rule" >/dev/null || {
    echo "ERROR: TPM rule must match only numbered tpmrm device nodes" >&2
    exit 1
}
grep -F 'RUN+="/usr/bin/setfacl --modify user:_ferrogate:rw- -- $env{DEVNAME}"' "$tpm_rule" >/dev/null || {
    echo "ERROR: TPM rule must grant only _ferrogate rw access through an ACL" >&2
    exit 1
}
if grep -E '(^|, )[A-Z]*(OWNER|GROUP|MODE)[:+]?=' "$tpm_rule" >/dev/null; then
    echo "ERROR: TPM rule must preserve the distribution's TPM owner, group and mode" >&2
    exit 1
fi

# The administrator client (F22) is the separate, optional
# ferrogate-mia-tray-admin package; every workstation gets this one.
if grep -Fx "./usr/bin/mia-tray-admin" "$work_dir/files" >/dev/null; then
    echo "ERROR: $deb must not contain /usr/bin/mia-tray-admin (ferrogate-mia-tray-admin ships it)" >&2
    exit 1
fi

depends=$(dpkg-deb --field "$deb" Depends)
for dependency in acl udev libgtk-3-0 policykit-1 systemd passwd; do
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
grep -F 'ferrogate-operators' "$work_dir/control/postinst" >/dev/null
grep -F 'chgrp "$STATUS_GROUP" "$config_file"' "$work_dir/control/postinst" >/dev/null
grep -F '[ ! -L "$config_file" ]' "$work_dir/control/postinst" >/dev/null
grep -F 'action.lookup("unit") === "mia.service"' "$work_dir/root/usr/share/polkit-1/rules.d/50-ferrogate-operators.rules" >/dev/null
grep -F 'subject.isInGroup("ferrogate-operators")' "$work_dir/root/usr/share/polkit-1/rules.d/50-ferrogate-operators.rules" >/dev/null
grep -F '_ferrogate' "$work_dir/control/postinst" >/dev/null
grep -F 'setfacl --modify "user:$SERVICE_USER:rw-"' "$work_dir/control/postinst" >/dev/null
grep -F 'udevadm control --reload-rules' "$work_dir/control/postinst" >/dev/null
grep -F 'setfacl --remove "user:$SERVICE_USER"' "$work_dir/control/postrm" >/dev/null
grep -F 'systemctl --user restart mia-tray.service' "$work_dir/control/postinst" >/dev/null
if grep -F '#DEBHELPER#' "$work_dir/control/postinst" >/dev/null; then
    echo "ERROR: cargo-deb did not expand #DEBHELPER# in postinst" >&2
    exit 1
fi

echo "OK: $deb contains MIA, tray, launcher, autostart, access groups, and lifecycle hooks"
