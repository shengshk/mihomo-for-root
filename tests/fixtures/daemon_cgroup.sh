#!/system/bin/sh
# Run as root in a private stage containing box.daemon and daemon.utils.
# Freeze only our disposable caller, never an Android app or a real service.
set -eu
cd "$(dirname "$0")"
stage=$(pwd)
[ "$(id -u)" = 0 ] || exit 77
[ -f /sys/fs/cgroup/cgroup.procs ] || exit 77
group="/sys/fs/cgroup/mfr-daemon-check-$$"
mkdir "$group"
parent=''
cleanup() {
  printf '0\n' > "$group/cgroup.freeze"
  if [ -n "$parent" ]; then kill "$parent" 2>/dev/null || true; wait "$parent" 2>/dev/null || true; fi
  rmdir "$group"
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP
cat > "$stage/parent.sh" <<'PARENT'
#!/system/bin/sh
set -e
printf '%s\n' "$$" > "$2/cgroup.procs"
"$1/box.daemon" /system/bin/sh "$1/child.sh" "$1" &
exec sleep 30
PARENT
cat > "$stage/child.sh" <<'CHILD'
#!/system/bin/sh
cat "/proc/$$/cgroup" > "$1/child.groups"
printf '%s\n' "$$" > "$1/child.ready"
sleep 1
printf 'alive\n' > "$1/child.result"
CHILD
/system/bin/sh "$stage/parent.sh" "$stage" "$group" > "$stage/parent.log" 2>&1 &
parent=$!
count=0
while [ ! -f "$stage/child.ready" ]; do count=$((count+1)); [ "$count" -lt 40 ] || exit 1; sleep 0.05; done
printf '1\n' > "$group/cgroup.freeze"
count=0
until grep -q '^frozen 1$' "$group/cgroup.events"; do count=$((count+1)); [ "$count" -lt 40 ] || exit 1; sleep 0.05; done
count=0
while [ ! -f "$stage/child.result" ]; do count=$((count+1)); [ "$count" -lt 40 ] || exit 1; sleep 0.05; done
busybox awk -F: '$3!="/" {bad=1} END {exit bad}' "$stage/child.groups"
grep -q '^alive$' "$stage/child.result"
echo 'PASS daemon exec left every app controller and ran while its caller stayed frozen'
