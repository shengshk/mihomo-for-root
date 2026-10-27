#!/system/bin/sh
set -eu
# Stage the fixture with binaries/utils, then run with busybox unshare -n.
# Refuse to alter the phone's real network namespace.
[ "$(readlink /proc/self/ns/net)" != "$(readlink /proc/1/ns/net)" ] || { echo 'Run inside an isolated network namespace.' >&2; exit 1; }
cd "$(dirname "$0")"
stage=$(pwd)
box_dir="$stage"
box_run="$stage/run"; box_run_state="$box_run/state"; bin_dir="$stage/bin"
mkdir -p "$box_run_state" "$bin_dir" "$stage/data"
cp "$stage/agh-dns-bridge" "$bin_dir/agh-dns-bridge"
. "$stage/ports.utils"
adg_bridge_pid="$box_run_state/adguardhome-bridge.pid"; adg_group=19054
adg_bridge_alive() {
 local p; p=$(cat "$adg_bridge_pid" 2>/dev/null)
 case "$p" in ''|*[!0-9]*) return 1 ;; esac
 kill -0 "$p" 2>/dev/null && grep -q '/bin/agh-dns-bridge' "/proc/$p/cmdline"
}
. "$stage/adg-capture.utils"
cleanup() {
 capture remove >/dev/null 2>&1 || true
 for file in "$stage/test-agh.pid" "$stage/test-upstream.pid" "$stage/test-upstream2.pid"; do
  [ ! -f "$file" ] || kill "$(cat "$file")" 2>/dev/null || true
 done
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP
ip link set lo up
ip -6 addr add fd00::2/128 dev lo
ip -6 route add 2001:db8::/32 dev lo
./probe -mode serve -address 127.0.0.1:11053 -answer 203.0.113.7 > upstream.log 2>&1 &
echo $! > test-upstream.pid
./probe -mode serve -address 127.0.0.1:11054 -answer 203.0.113.8 > upstream2.log 2>&1 &
echo $! > test-upstream2.pid
cat > test-agh.yaml <<'YAML'
http:
  address: 127.0.0.1:19092
users: []
dns:
  bind_hosts: [127.0.0.1]
  port: 1054
  upstream_dns: [127.0.0.1:11053]
  fallback_dns: []
  cache_enabled: false
  cache_size: 1048576
  ratelimit: 0
filtering:
  protection_enabled: false
querylog:
  enabled: false
statistics:
  enabled: false
schema_version: 34
YAML
busybox setuidgid 0:19054 ./AdGuardHome -c "$stage/test-agh.yaml" -w "$stage/data" --no-check-update > test-agh.log 2>&1 &
echo $! > test-agh.pid
count=0
until /system/bin/curl -fsS --noproxy '*' --max-time 1 http://127.0.0.1:19092/control/status >/dev/null 2>&1; do
 count=$((count+1)); [ "$count" -lt 8 ] || exit 1; sleep 1
done
capture install
# A core IPv6-off policy must not disable the independent DNS transport.
if [ -f "$stage/ipv6-policy.utils" ]; then
 . "$stage/ipv6-policy.utils"
 pref=100; adguardhome_enabled=true
 disable_ipv6
fi
[ "$(cat "$box_run_state/adguardhome.capture")" = dual-tproxy ]
./probe -proto udp4 -address 127.0.0.2:53
./probe -proto tcp4 -address 127.0.0.2:53
./probe -proto udp6
./probe -proto tcp6
./probe -proto udp6 -qtype 28 -answer 2001:db8::7
./probe -proto tcp6 -qtype 28 -answer 2001:db8::7
bridge_pid=$(cat "$adg_bridge_pid")
/system/bin/curl -fsS --noproxy '*' --max-time 3 -H 'Content-Type: application/json' --data '{"upstream_dns":["127.0.0.1:11054"]}' http://127.0.0.1:19092/control/dns_config >/dev/null
./probe -proto udp6 -answer 203.0.113.8
./probe -proto tcp6 -answer 203.0.113.8
[ "$(cat "$adg_bridge_pid")" = "$bridge_pid" ]
capture install
[ "$(cat "$adg_bridge_pid")" = "$bridge_pid" ]
capture remove
[ ! -f "$adg_bridge_pid" ]
! ip6tables -t mangle -S OUTPUT | grep -q MFR_AGH6
! ip -6 rule show pref "$adg_v6_pref" | grep -q "$adg_v6_table"
echo 'PASS upstream switch, idempotent apply and complete withdrawal'
