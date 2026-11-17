#!/bin/sh
# SARF installer for Linux.
#
# Installs a prebuilt `sarf` binary, creates a dedicated system user and data
# directory, seeds the configuration with `sarf init`, and (when systemd is
# available) installs the hardened unit from deploy/sarf.service.
#
# Usage:
#   sh scripts/install.sh [options]
#
# Options:
#   --binary PATH     Prebuilt binary (default: <repo>/target/release/sarf)
#   --prefix PATH     Install prefix (default: /usr/local)
#   --data-dir PATH   Data/config directory (default: /var/lib/sarf)
#   --user NAME       Service user and group (default: sarf)
#   --unit PATH       systemd unit template (default: <repo>/deploy/sarf.service)
#   --no-systemd      Do not install or reload the systemd unit
#   --start           Enable and start the unit now (requires systemd)
#   --docker-group    Add the service user to the docker group (root-equivalent)
#   -h, --help        Show this help
#
# The installer is idempotent. It never downloads anything, never starts the
# service unless --start is given, and does not assume sudo: run it as root.
#
# Uninstall (manual; deliberately not automated because it can destroy data).
# Substitute your --prefix/--data-dir/--user values where they differ:
#   systemctl disable --now sarf.service 2>/dev/null || true
#   rm -f /etc/systemd/system/sarf.service
#   systemctl daemon-reload 2>/dev/null || true
#   rm -f /usr/local/bin/sarf
#   userdel sarf 2>/dev/null || true
#   groupdel sarf 2>/dev/null || true
#   rm -rf /var/lib/sarf     # WARNING: deletes all recorded history
#
set -eu

umask 022

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(dirname -- "$SCRIPT_DIR")

PREFIX=/usr/local
DATA_DIR=/var/lib/sarf
RUN_USER=sarf
RUN_GROUP=sarf
BINARY="$REPO_ROOT/target/release/sarf"
UNIT_SRC="$REPO_ROOT/deploy/sarf.service"
INSTALL_SYSTEMD=1
START=0
JOIN_DOCKER_GROUP=0

usage() {
    cat <<'EOF'
Install SARF from a locally built binary.

Usage: sh scripts/install.sh [options]

Options:
  --binary PATH     Prebuilt binary (default: <repo>/target/release/sarf)
  --prefix PATH     Install prefix (default: /usr/local)
  --data-dir PATH   Data/config directory (default: /var/lib/sarf)
  --user NAME       Service user and group (default: sarf)
  --unit PATH       systemd unit template (default: <repo>/deploy/sarf.service)
  --no-systemd      Do not install or reload the systemd unit
  --start           Enable and start the unit now (requires systemd)
  --docker-group    Add the service user to the docker group (root-equivalent)
  -h, --help        Show this help

Run as root. The service is not started unless --start is passed.
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

note() {
    printf '%s\n' "$*"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --binary)
            [ "$#" -ge 2 ] || die "--binary needs a path"
            BINARY=$2
            shift 2
            ;;
        --binary=*)
            BINARY=${1#*=}
            shift
            ;;
        --prefix)
            [ "$#" -ge 2 ] || die "--prefix needs a path"
            PREFIX=$2
            shift 2
            ;;
        --prefix=*)
            PREFIX=${1#*=}
            shift
            ;;
        --data-dir)
            [ "$#" -ge 2 ] || die "--data-dir needs a path"
            DATA_DIR=$2
            shift 2
            ;;
        --data-dir=*)
            DATA_DIR=${1#*=}
            shift
            ;;
        --user)
            [ "$#" -ge 2 ] || die "--user needs a name"
            RUN_USER=$2
            RUN_GROUP=$2
            shift 2
            ;;
        --user=*)
            RUN_USER=${1#*=}
            RUN_GROUP=$RUN_USER
            shift
            ;;
        --unit)
            [ "$#" -ge 2 ] || die "--unit needs a path"
            UNIT_SRC=$2
            shift 2
            ;;
        --unit=*)
            UNIT_SRC=${1#*=}
            shift
            ;;
        --no-systemd)
            INSTALL_SYSTEMD=0
            shift
            ;;
        --start)
            START=1
            shift
            ;;
        --docker-group)
            JOIN_DOCKER_GROUP=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            [ "$#" -eq 0 ] || die "unexpected argument: $1"
            ;;
        -*)
            die "unknown option: $1 (try --help)"
            ;;
        *)
            die "unexpected argument: $1 (try --help)"
            ;;
    esac
done

[ -n "$PREFIX" ] || die "--prefix must not be empty"
[ -n "$DATA_DIR" ] || die "--data-dir must not be empty"
[ -n "$RUN_USER" ] || die "--user must not be empty"

# Account names are interpolated into commands and the unit's User=/Group=.
case "$RUN_USER" in
    -*|*[!a-z0-9_-]*) die "invalid user name: $RUN_USER" ;;
esac
case "$RUN_GROUP" in
    -*|*[!a-z0-9_-]*) die "invalid group name: $RUN_GROUP" ;;
esac

case "$PREFIX" in
    /*) ;;
    *) die "--prefix must be an absolute path: $PREFIX" ;;
esac
case "$DATA_DIR" in
    /*) ;;
    *) die "--data-dir must be an absolute path: $DATA_DIR" ;;
esac

# Refuse paths that would make the recursive ownership change dangerous.
case "$PREFIX" in
    /) die "refusing to use / as the install prefix" ;;
esac
case "$DATA_DIR" in
    /) die "refusing to use / as the data directory" ;;
esac
case "$PREFIX/" in
    */../*) die "--prefix must not contain '..' components: $PREFIX" ;;
esac
case "$DATA_DIR/" in
    */../*) die "--data-dir must not contain '..' components: $DATA_DIR" ;;
esac

# Normalize trailing slashes. Repeated slashes can otherwise turn "//" into
# "/" after the root check above.
while [ "$PREFIX" != "${PREFIX%/}" ]; do
    PREFIX=${PREFIX%/}
done
while [ "$DATA_DIR" != "${DATA_DIR%/}" ]; do
    DATA_DIR=${DATA_DIR%/}
done
[ -n "$PREFIX" ] || die "invalid install prefix"
[ -n "$DATA_DIR" ] || die "invalid data directory"
case "$PREFIX" in
    /) die "refusing to use / as the install prefix" ;;
esac
case "$DATA_DIR" in
    /) die "refusing to use / as the data directory" ;;
esac

if [ "$START" -eq 1 ] && [ "$INSTALL_SYSTEMD" -eq 0 ]; then
    die "--start cannot be combined with --no-systemd"
fi

if [ "$JOIN_DOCKER_GROUP" -eq 1 ]; then
    command -v usermod >/dev/null 2>&1 || die "usermod is required for --docker-group"
    if command -v getent >/dev/null 2>&1; then
        getent group docker >/dev/null 2>&1 || die "--docker-group requested but the docker group does not exist"
    else
        grep -q "^docker:" /etc/group 2>/dev/null || die "--docker-group requested but the docker group does not exist"
    fi
fi

if [ "$(id -u)" -ne 0 ]; then
    die "this is a system-wide install; run it as root"
fi

command -v install >/dev/null 2>&1 || die "the 'install' utility is required"
command -v useradd >/dev/null 2>&1 || die "useradd is required to create the service user"
command -v groupadd >/dev/null 2>&1 || die "groupadd is required to create the service group"

# Resolve the binary to an absolute path so a later cd can never change it.
case "$BINARY" in
    /*) ;;
    *)
        BINARY_DIR=$(dirname -- "$BINARY")
        BINARY_NAME=$(basename -- "$BINARY")
        [ -d "$BINARY_DIR" ] || die "binary directory not found: $BINARY_DIR"
        BINARY_PARENT=$(CDPATH= cd -- "$BINARY_DIR" && pwd) \
            || die "cannot resolve binary directory: $BINARY_DIR"
        BINARY="$BINARY_PARENT/$BINARY_NAME"
        ;;
esac

[ -f "$BINARY" ] || die "binary not found: $BINARY (build it first with: cargo build --release)"
[ -x "$BINARY" ] || die "binary is not executable: $BINARY"

# Never recursively chown through a symlinked data directory.
[ ! -L "$DATA_DIR" ] || die "data directory must not be a symlink: $DATA_DIR"

if [ "$INSTALL_SYSTEMD" -eq 1 ]; then
    [ -f "$UNIT_SRC" ] || die "systemd unit not found: $UNIT_SRC"
fi

if [ "$START" -eq 1 ]; then
    if [ ! -d /run/systemd/system ] || [ ! -d /etc/systemd/system ] || ! command -v systemctl >/dev/null 2>&1; then
        die "--start requires a running systemd"
    fi
fi

# --- service account -------------------------------------------------------

if command -v getent >/dev/null 2>&1; then
    group_exists() { getent group "$1" >/dev/null 2>&1; }
else
    group_exists() { grep -q "^$1:" /etc/group 2>/dev/null; }
fi

if ! group_exists "$RUN_GROUP"; then
    groupadd --system "$RUN_GROUP"
    note "Created system group: $RUN_GROUP"
fi

if ! id -u "$RUN_USER" >/dev/null 2>&1; then
    NOLOGIN=/usr/sbin/nologin
    if [ -x /sbin/nologin ]; then
        NOLOGIN=/sbin/nologin
    fi
    useradd --system \
        --gid "$RUN_GROUP" \
        --home-dir "$DATA_DIR" \
        --no-create-home \
        --shell "$NOLOGIN" \
        "$RUN_USER"
    note "Created system user: $RUN_USER"
fi

# --- directories and binary ------------------------------------------------

[ -d "$PREFIX" ] || install -d -m 0755 "$PREFIX"
[ -d "$PREFIX/bin" ] || install -d -m 0755 "$PREFIX/bin"

# The data directory is private to the service user. `sarf init` below creates
# the database/config layout with its own tighter file modes; the recursive
# chown after init makes the result independent of the invoking umask.
install -d -m 0750 -o "$RUN_USER" -g "$RUN_GROUP" "$DATA_DIR"

BIN_DEST="$PREFIX/bin/sarf"
if [ "$BINARY" != "$BIN_DEST" ]; then
    # Install to a temporary name and rename, so a running service keeps a valid
    # executable and a failed copy never leaves a truncated binary behind.
    tmp_bin="$BIN_DEST.tmp.$$"
    trap 'rm -f "$tmp_bin"' 0 1 2 15
    install -m 0755 "$BINARY" "$tmp_bin"
    mv -f "$tmp_bin" "$BIN_DEST"
    trap - 0 1 2 15
else
    chmod 0755 "$BIN_DEST"
fi
chown root:root "$BIN_DEST"
chmod 0755 "$BIN_DEST"
note "Installed binary: $BIN_DEST"

# --- configuration ---------------------------------------------------------

note "Initializing data directory: $DATA_DIR"
if ! "$BIN_DEST" init --data-dir "$DATA_DIR"; then
    die "sarf init failed; the configuration was not seeded"
fi
chown -R "$RUN_USER:$RUN_GROUP" "$DATA_DIR"
chmod 0750 "$DATA_DIR"
note "Configuration: $DATA_DIR/sarf.toml"

if [ "$JOIN_DOCKER_GROUP" -eq 1 ]; then
    usermod -aG docker "$RUN_USER"
    note "Added $RUN_USER to the docker group."
    note "WARNING: docker group membership is root-equivalent. Remove it if full Docker metadata/logs are not required."
fi

# --- systemd ---------------------------------------------------------------

UNIT_INSTALLED=0
if [ "$INSTALL_SYSTEMD" -eq 1 ]; then
    if command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd/system ]; then
        UNIT_DEST=/etc/systemd/system/sarf.service

        if [ "$PREFIX" = /usr/local ] && [ "$DATA_DIR" = /var/lib/sarf ] \
            && [ "$RUN_USER" = sarf ] && [ "$RUN_GROUP" = sarf ]; then
            # Fast path: the checked-in unit already contains exactly these
            # paths and the default service account.
            install -m 0644 "$UNIT_SRC" "$UNIT_DEST"
        else
            # The shipped unit documents the default paths/account. Rewrite the
            # functional settings for a custom prefix, data directory or user
            # rather than silently installing a unit that points at the wrong
            # places or account.
            case "$PREFIX$DATA_DIR" in
                *%*|*'$'*)
                    die "systemd unit paths cannot contain '%' or '\$'; choose another path or use --no-systemd"
                    ;;
            esac

            # Escape a value for the replacement side of sed (delimiter is |).
            sed_replacement() {
                printf '%s' "$1" | sed -e 's/[\\&|]/\\&/g'
            }
            # Quote a systemd setting value only when it contains whitespace or
            # characters that need C-style escaping.
            systemd_value() {
                case "$1" in
                    *[[:space:]]*|*'"'*|*\\*)
                        escaped=$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
                        printf '"%s"' "$escaped"
                        ;;
                    *)
                        printf '%s' "$1"
                        ;;
                esac
            }

            unit_bin=$(systemd_value "$BIN_DEST")
            unit_data=$(systemd_value "$DATA_DIR")
            unit_config=$(systemd_value "$DATA_DIR/sarf.toml")
            unit_tmp="$UNIT_DEST.tmp.$$"
            trap 'rm -f "$unit_tmp"' 0 1 2 15
            # Replace whole functional lines, not path substrings: quoting a
            # path with spaces must not leave the "/sarf.toml" suffix outside
            # the quotes, and sequential substring substitutions can corrupt
            # paths that contain another default path as a prefix.
            sed \
                -e "s|^ExecStart=.*$|ExecStart=$(sed_replacement "$unit_bin") run --data-dir $(sed_replacement "$unit_data") --config $(sed_replacement "$unit_config")|" \
                -e "s|^User=.*$|User=$(sed_replacement "$RUN_USER")|" \
                -e "s|^Group=.*$|Group=$(sed_replacement "$RUN_GROUP")|" \
                -e "s|^WorkingDirectory=.*$|WorkingDirectory=$(sed_replacement "$unit_data")|" \
                -e "s|^ReadWritePaths=.*$|ReadWritePaths=$(sed_replacement "$unit_data")|" \
                "$UNIT_SRC" > "$unit_tmp"
            chmod 0644 "$unit_tmp"
            mv -f "$unit_tmp" "$UNIT_DEST"
            trap - 0 1 2 15
        fi

        if [ "$JOIN_DOCKER_GROUP" -eq 1 ]; then
            # Docker socket access is root-equivalent; this is opt-in only.
            if ! grep -q '^SupplementaryGroups=docker$' "$UNIT_DEST"; then
                sed -i '/^Group=/a SupplementaryGroups=docker' "$UNIT_DEST"
            fi
        fi

        UNIT_INSTALLED=1
        note "Installed systemd unit: $UNIT_DEST"

        if [ -d /run/systemd/system ]; then
            systemctl daemon-reload
            if [ "$START" -eq 1 ]; then
                systemctl enable sarf.service
                # `enable --now` does not restart an already-running unit, so an
                # upgrade would keep executing the old binary. restart also starts
                # an inactive unit, which is the desired first-install behavior.
                systemctl restart sarf.service
                note "Enabled and (re)started sarf.service"
            else
                note "sarf.service is installed; --start was not given."
                note "Enable at boot: systemctl enable sarf.service"
                note "Start now:     systemctl start sarf.service"
            fi
        else
            note "systemd is not running; the unit was installed but not reloaded."
        fi
    else
        note "systemd not detected; skipping unit installation (--no-systemd also skips it)."
    fi
else
    note "Skipping systemd unit installation (--no-systemd)."
fi

# --- summary ---------------------------------------------------------------

printf '\nSARF installed.\n'
printf '  binary:   %s\n' "$BIN_DEST"
printf '  data dir: %s\n' "$DATA_DIR"
printf '  config:   %s\n' "$DATA_DIR/sarf.toml"
if [ "$UNIT_INSTALLED" -eq 1 ] && [ "$START" -eq 0 ]; then
    printf '  service:  installed (--start not given)\n'
elif [ "$START" -eq 1 ]; then
    printf '  service:  started\n'
else
    printf '  service:  not installed\n'
fi

printf '\nVerify the installation (the data directory is private to %s):\n' "$RUN_USER"
printf '  sudo "%s" doctor --data-dir "%s"\n' "$BIN_DEST" "$DATA_DIR"
printf '  sudo "%s" status --data-dir "%s"\n' "$BIN_DEST" "$DATA_DIR"
