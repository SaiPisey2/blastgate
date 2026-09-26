#!/usr/bin/env bash
# kind-gateway.sh prints the IPv4 gateway of the kind docker network: the
# host as the kind node sees it, where the e2e webhook tests listen.
#
# kind creates its network with an IPv6 subnet, so the IPv4 entry is not
# always first in .IPAM.Config, and a subnet docker chose itself can have
# an empty Gateway field. Take the first IPv4 subnet, and its .1 address
# when no gateway is recorded (docker's default for a bridge network).
set -euo pipefail

docker network inspect kind -f '{{range .IPAM.Config}}{{.Subnet}} {{.Gateway}}{{"\n"}}{{end}}' |
	awk '$1 ~ /^[0-9.]+\/[0-9]+$/ {
		if ($2 ~ /^[0-9.]+$/) { print $2; exit }
		split($1, a, "/"); split(a[1], o, ".")
		print o[1] "." o[2] "." o[3] ".1"; exit
	}'
