
# Reverse VPNs with _revsh_.

### What are Tun / Tap devices?

### When would I use one instead of the other?

## Examples

### Setting up a Tap bridge.

Target:

	export BRIDGE_IF="br0"
	export TAP_IF="tap0"
	export ETH_IF="ens37"

	ip link add $BRIDGE_IF type bridge
	ip link set $BRIDGE_IF up
	ip link set $TAP_IF up
	ip link set $TAP_IF master $BRIDGE_IF
	ip link set $ETH_IF up
	ip link set $ETH_IF master $BRIDGE_IF

Control:

	export TAP_IF="tap0"

	dhclient $TAP_IF

### Setting up a Tun route.

Target:

	export TUN_IF="tun0"
	export TUN_LOCAL_IP="192.168.50.1"
	export TUN_REMOTE_IP="192.168.50.2"
	export TUN_NET="192.168.50.0/24"
	export ETH_NET="10.5.120.0/24"
	export ETH_IF="ens33"

	echo 1 >/proc/sys/net/ipv4/ip_forward
	iptables -t nat -A POSTROUTING -s $TUN_NET -o $ETH_IF -j MASQUERADE
	ip addr add $TUN_REMOTE_IP dev $TUN_IF peer $TUN_LOCAL_IP
	ip link set $TUN_IF up

Control:

	export TUN_IF="tun0"
	export TUN_LOCAL_IP="192.168.50.1"
	export TUN_REMOTE_IP="192.168.50.2"
	export TUN_NET="192.168.50.0/24"
	export ETH_NET="10.5.120.0/24"
	export ETH_IF="eth0"

	ip addr add $TUN_LOCAL_IP dev $TUN_IF peer $TUN_REMOTE_IP
	ip link set $TUN_IF up
	ip route add $ETH_NET via $TUN_LOCAL_IP

