#!/bin/sh
# Real enforcement tests execute only in a disposable user/network namespace.
set -eu
cd "$(dirname "$0")/.."
binary=$(mktemp /tmp/firewall-test.XXXXXXXX)
trap 'rm -f "$binary"' EXIT HUP INT TERM
go test -c -race -o "$binary" ./backend/linux
parent_netns=$(readlink /proc/self/ns/net)
FIREWALL_ISOLATED_TEST=1 FIREWALL_PARENT_NETNS="$parent_netns" unshare --user --map-root-user --net -- "$binary" -test.v -test.run 'TestKernel'
