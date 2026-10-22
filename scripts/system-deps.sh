#!/usr/bin/env bash
# Make sure everything Carrier needs from the system is in place, and install
# whatever is missing. Every imlazy command that builds or runs Carrier
# depends on this, so a fresh checkout needs nothing done by hand.
#
# On Raven it installs through `rvn`; elsewhere through the distribution's own
# package manager (pacman, apt, dnf, zypper, xbps, apk), with each package
# translated to that distribution's name for it.
#
# Checked by what Carrier actually runs -- a command on PATH, a subordinate
# ID range for this user, newuidmap being allowed to use it -- rather than by
# package name, so it costs a few milliseconds when all is well and also
# counts things installed some other way.
#
#   scripts/system-deps.sh           install what is missing
#   scripts/system-deps.sh --check   only report; exit 1 if anything is missing
set -euo pipefail

check_only=false
[[ ${1:-} == --check ]] && check_only=true

# Containers on macOS run in Carrier's bundled VM, which `carrier doctor`
# sets up; nothing here applies there.
if [[ $(uname -s) != Linux ]]; then
    exit 0
fi

user="${SUDO_USER:-$USER}"

# ---------------------------------------------------------------- packages --

# Which family of package names this machine uses, and how to install.
family=""
installer=()
if command -v rvn >/dev/null 2>&1; then
    # Official repositories only: everything is there, and nothing here
    # should quietly build something from the AUR.
    family=arch; installer=(rvn install --repo-only --yes)
elif command -v pacman >/dev/null 2>&1; then
    family=arch; installer=(pacman -S --needed --noconfirm)
elif command -v apt-get >/dev/null 2>&1; then
    family=debian; installer=(apt-get install -y)
elif command -v dnf >/dev/null 2>&1; then
    family=fedora; installer=(dnf install -y)
elif command -v zypper >/dev/null 2>&1; then
    family=suse; installer=(zypper --non-interactive install)
elif command -v xbps-install >/dev/null 2>&1; then
    family=void; installer=(xbps-install -Sy)
elif command -v apk >/dev/null 2>&1; then
    family=alpine; installer=(apk add)
fi

# Carrier runs crun when runc is missing, but runc is what it is tested
# against, so it is installed either way. slirp4netns is the network helper
# Carrier starts; pasta is checked for by `carrier doctor`.
#
# command | arch | debian | fedora | suse | void | alpine
requirements=(
    "cargo|rust|cargo|cargo|cargo|cargo|cargo"
    "runc|runc|runc|runc|runc|runc|runc"
    "fuse-overlayfs|fuse-overlayfs|fuse-overlayfs|fuse-overlayfs|fuse-overlayfs|fuse-overlayfs|fuse-overlayfs"
    "fusermount3|fuse3|fuse3|fuse3|fuse3|fuse3|fuse3"
    "slirp4netns|slirp4netns|slirp4netns|slirp4netns|slirp4netns|slirp4netns|slirp4netns"
    "pasta|passt|passt|passt|passt|passt|passt"
    "nsenter|util-linux|util-linux|util-linux|util-linux|util-linux|util-linux"
    "newuidmap|shadow|uidmap|shadow-utils|shadow|shadow|shadow-uidmap"
    "usermod|shadow|passwd|shadow-utils|shadow|shadow|shadow"
    "setcap|libcap|libcap2-bin|libcap|libcap-progs|libcap-progs|libcap-setcap"
)

package_for() {
    local -a cols
    IFS='|' read -ra cols <<<"$1"
    case $family in
        arch) echo "${cols[1]}" ;;
        debian) echo "${cols[2]}" ;;
        fedora) echo "${cols[3]}" ;;
        suse) echo "${cols[4]}" ;;
        void) echo "${cols[5]}" ;;
        alpine) echo "${cols[6]}" ;;
        *) echo "${cols[1]}" ;;
    esac
}

missing_packages() {
    for requirement in "${requirements[@]}"; do
        command -v "${requirement%%|*}" >/dev/null 2>&1 || package_for "$requirement"
    done | sort -u
}

# ------------------------------------------------------- user namespaces --

# Without a subordinate range in /etc/subuid and /etc/subgid only container
# UID 0 can be mapped, and images that switch to another user break.
has_range() { grep -qE "^($user|$(id -u "$user")):" "$1" 2>/dev/null; }

# First ID past every range already handed out, so the new one overlaps
# nothing, and never below the conventional 100000.
next_free_id() {
    cat /etc/subuid /etc/subgid 2>/dev/null |
        awk -F: 'NF >= 3 { end = $2 + $3; if (end > max) max = end }
                 END { print (max > 100000 ? max : 100000) }'
}

# newuidmap and newgidmap write another user's IDs into the map, so they need
# setuid or file capabilities. Packages ship them with capabilities, and an
# install that drops extended attributes leaves them with neither.
idmap_privileged() {
    local path
    path="$(readlink -f "$(command -v "$1")")"
    [[ -u $path ]] || getcap "$path" 2>/dev/null | grep -q "$2"
}
idmap_ready() {
    command -v newuidmap >/dev/null 2>&1 || return 0  # installed below
    command -v getcap >/dev/null 2>&1 || return 1
    idmap_privileged newuidmap cap_setuid && idmap_privileged newgidmap cap_setgid
}

# ------------------------------------------------------------------- report --

mapfile -t missing < <(missing_packages)
needs_subuid=false
has_range /etc/subuid || needs_subuid=true
needs_subgid=false
has_range /etc/subgid || needs_subgid=true
needs_idmap_caps=false
idmap_ready || needs_idmap_caps=true
needs_fuse=false
[[ -e /dev/fuse ]] || needs_fuse=true

if ((${#missing[@]} == 0)) && ! $needs_subuid && ! $needs_subgid &&
    ! $needs_idmap_caps && ! $needs_fuse; then
    exit 0
fi

((${#missing[@]} > 0)) && echo "Carrier needs these packages: ${missing[*]}"
$needs_subuid && echo "Carrier needs a subordinate UID range for $user in /etc/subuid"
$needs_subgid && echo "Carrier needs a subordinate GID range for $user in /etc/subgid"
$needs_idmap_caps && echo "Carrier needs newuidmap/newgidmap to have their capabilities"
$needs_fuse && echo "Carrier needs /dev/fuse (the fuse kernel module)"
if $check_only; then
    exit 1
fi

sudo=()
((EUID == 0)) || sudo=(sudo)

# ------------------------------------------------------------------ install --

if ((${#missing[@]} > 0)); then
    if [[ -z $family ]]; then
        echo "No supported package manager found; install these yourself: ${missing[*]}" >&2
        exit 1
    fi
    [[ $family == debian ]] && "${sudo[@]}" apt-get update -qq
    "${sudo[@]}" "${installer[@]}" "${missing[@]}"
fi

if $needs_subuid || $needs_subgid; then
    start=$(next_free_id)
    range="$start-$((start + 65535))"
    args=()
    $needs_subuid && args+=(--add-subuids "$range")
    $needs_subgid && args+=(--add-subgids "$range")
    echo "==> Giving $user the subordinate ID range $range"
    "${sudo[@]}" usermod "${args[@]}" "$user"
fi

# Checked again: the shadow package may only just have been installed.
if ! idmap_ready; then
    echo "==> Restoring the capabilities of newuidmap and newgidmap"
    "${sudo[@]}" setcap cap_setuid+ep "$(readlink -f "$(command -v newuidmap)")"
    "${sudo[@]}" setcap cap_setgid+ep "$(readlink -f "$(command -v newgidmap)")"
fi

if $needs_fuse; then
    echo "==> Loading the fuse module"
    "${sudo[@]}" modprobe fuse
fi

# ------------------------------------------------------------------- verify --

# Say so if the install did not provide what was missing, rather than letting
# a container fail with "No such file or directory" further down.
mapfile -t still < <(missing_packages)
if ((${#still[@]} > 0)); then
    echo "Still missing after install: ${still[*]}" >&2
    exit 1
fi
if ! idmap_ready; then
    echo "newuidmap/newgidmap still lack the capabilities to map IDs." >&2
    exit 1
fi

# Containers already set up by podman keep the old single-ID mapping until
# it is told about the new range.
if ($needs_subuid || $needs_subgid) && command -v podman >/dev/null 2>&1; then
    podman system migrate >/dev/null 2>&1 || true
fi
echo "System dependencies installed."
