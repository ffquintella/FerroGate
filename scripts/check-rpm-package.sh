#!/bin/sh
# Static contract check for the RPM agent installer. It inspects the archive
# without installing it, so it cannot alter users, services, udev or the TPM.
set -eu

rpm_package=${1:?usage: check-rpm-package.sh path/to/ferrogate-mia.rpm}
if [ ! -f "$rpm_package" ]; then
    echo "ERROR: RPM package not found: $rpm_package" >&2
    exit 1
fi

[ "$(rpm -qp --queryformat '%{NAME}' "$rpm_package")" = ferrogate-mia ] || {
    echo "ERROR: unexpected RPM package name" >&2
    exit 1
}

rpm -qpl "$rpm_package" | grep -Fx '/usr/lib/udev/rules.d/70-ferrogate-mia-tpm.rules' >/dev/null || {
    echo "ERROR: RPM does not contain the FerroGate TPM udev rule" >&2
    exit 1
}

requires=$(rpm -qp --requires "$rpm_package")
for dependency in acl shadow-utils systemd systemd-udev tpm2-tss; do
    printf '%s\n' "$requires" | grep -Fx "$dependency" >/dev/null || {
        echo "ERROR: missing RPM dependency $dependency" >&2
        exit 1
    }
done

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
rpm_abs=$(readlink -f "$rpm_package")
(cd "$work_dir" && rpm2cpio "$rpm_abs" | cpio -id --quiet \
    ./usr/lib/udev/rules.d/70-ferrogate-mia-tpm.rules)
tpm_rule="$work_dir/usr/lib/udev/rules.d/70-ferrogate-mia-tpm.rules"
grep -F 'ACTION=="add|change"' "$tpm_rule" >/dev/null
grep -F 'SUBSYSTEM=="tpmrm"' "$tpm_rule" >/dev/null
grep -F 'KERNEL=="tpmrm[0-9]*"' "$tpm_rule" >/dev/null
grep -F 'RUN+="/usr/bin/setfacl --modify user:_ferrogate:rw- -- $env{DEVNAME}"' "$tpm_rule" >/dev/null
if grep -E '(^|, )[A-Z]*(OWNER|GROUP|MODE)[:+]?=' "$tpm_rule" >/dev/null; then
    echo "ERROR: TPM rule must preserve the distribution's TPM owner, group and mode" >&2
    exit 1
fi

scripts="$work_dir/scripts"
rpm -qp --scripts "$rpm_package" >"$scripts"
grep -F 'setfacl --modify "user:$SERVICE_USER:rw-"' "$scripts" >/dev/null
grep -F 'setfacl --modify "user:$SERVICE_USER:r--"' "$scripts" >/dev/null
grep -F 'udevadm control --reload-rules' "$scripts" >/dev/null
grep -F 'setfacl --remove "user:$SERVICE_USER"' "$scripts" >/dev/null
grep -F 'if [ "${1:-0}" -ne 0 ]' "$scripts" >/dev/null || {
    echo "ERROR: RPM removal must preserve the ACL during upgrades" >&2
    exit 1
}

echo "OK: $rpm_package contains the least-privilege TPM ACL and lifecycle hooks"
