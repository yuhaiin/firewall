#!/usr/bin/env bash
# Native veth/router throughput harness. Never modifies the invoking netns.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
if [[ ${1:-} != --isolated ]]; then
  for tool in unshare nsenter ip iperf3 go; do command -v "$tool" >/dev/null; done
  cd "$script_dir/.."
  build_dir=$(mktemp -d /tmp/firewall-benchmark.XXXXXXXX)
  trap 'rm -rf -- "$build_dir"' EXIT
  go build -o "$build_dir/policy-loader" ./examples/benchmark-linux
  parent_netns=$(readlink /proc/self/ns/net)
  output_dir=$(mktemp -d "${PWD}/firewall-benchmark-results.XXXXXXXX")
  FIREWALL_BENCH_PARENT_NS="$parent_netns" unshare --user --map-root-user --net -- \
    "$BASH" "$0" --isolated "$build_dir/policy-loader" "$output_dir"
  echo "Native benchmark JSON: $output_dir"
  exit
fi
[[ -n ${FIREWALL_BENCH_PARENT_NS:-} && $(readlink /proc/self/ns/net) != "$FIREWALL_BENCH_PARENT_NS" ]] || exit 1
loader=$2
output=$3
fw_pid= server_pid= left_pid= right_pid=
cleanup() {
  for pid in "$fw_pid" "$server_pid" "$left_pid" "$right_pid"; do
    if [[ -n $pid ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  done
}
trap cleanup EXIT INT TERM
unshare --net -- sleep infinity & left_pid=$!
unshare --net -- sleep infinity & right_pid=$!
for pid in "$left_pid" "$right_pid"; do
  for _ in {1..100}; do
    [[ $(readlink "/proc/$pid/ns/net") != $(readlink /proc/self/ns/net) ]] && break
    sleep .01
  done
done
setup_link() {
  local side=$1 pid=$2 subnet=$3
  ip link add "${side}0" type veth peer name "${side}1"
  ip link set "${side}1" netns "$pid"
  ip link set "${side}0" up
  ip addr add "10.80.$subnet.1/24" dev "${side}0"
  ip -6 addr add "fd42:$subnet::1/64" dev "${side}0" nodad
  ip -6 addr flush dev "${side}0" scope link
  ip -6 addr add fe80::1/64 dev "${side}0" nodad
  nsenter -t "$pid" -n -- ip link set lo up
  nsenter -t "$pid" -n -- ip link set "${side}1" up
  nsenter -t "$pid" -n -- ip addr add "10.80.$subnet.2/24" dev "${side}1"
  nsenter -t "$pid" -n -- ip route add default via "10.80.$subnet.1"
  nsenter -t "$pid" -n -- ip -6 addr add "fd42:$subnet::2/64" dev "${side}1" nodad
  nsenter -t "$pid" -n -- ip -6 addr flush dev "${side}1" scope link
  nsenter -t "$pid" -n -- ip -6 addr add fe80::2/64 dev "${side}1" nodad
  nsenter -t "$pid" -n -- ip -6 route add default via "fd42:$subnet::1"
}
setup_link left "$left_pid" 1
setup_link right "$right_pid" 2
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
mkdir -m 700 "$output/locks"
uname -a > "$output/environment.txt"
go version >> "$output/environment.txt"
iperf3 --version >> "$output/environment.txt" 2>&1
seconds=${FIREWALL_BENCH_SECONDS:-30}
repeats=${FIREWALL_BENCH_REPEATS:-5}
for rules in ${FIREWALL_BENCH_RULE_COUNTS:-0 100 1000 10000}; do
  if ((rules > 0)); then
    "$loader" -rules "$rules" -lock-dir "$output/locks" -ready "$output/ready-$rules" & fw_pid=$!
    for _ in {1..200}; do
      [[ -e "$output/ready-$rules" ]] && break
      kill -0 "$fw_pid"
      sleep .05
    done
    [[ -e "$output/ready-$rules" ]]
  fi
  for family in 4 6; do
    address=10.80.2.2
    [[ $family == 6 ]] && address=fd42:2::2
    for protocol in tcp udp; do
      for ((run=1; run<=repeats; run++)); do
        name="rules-$rules-ip$family-$protocol-$run"
        nsenter -t "$right_pid" -n -- iperf3 -s -1 "-$family" -B "$address" -J > "$output/$name-server.json" & server_pid=$!
        sleep .2
        options=()
        [[ $protocol == udp ]] && options=(-u -b "${FIREWALL_BENCH_UDP_RATE:-1G}")
        nsenter -t "$left_pid" -n -- iperf3 -c "$address" "-$family" -t "$seconds" -J "${options[@]}" > "$output/$name-client.json"
        wait "$server_pid"
        server_pid=
      done
    done
  done
  if [[ -n $fw_pid ]]; then kill -INT "$fw_pid"; wait "$fw_pid"; fw_pid=; fi
done
