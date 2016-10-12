
# Reverse VPNs with _revsh_.

### What are Tun / Tap devices?

### When would I use one instead of the other?

## Examples

### Setting up a Tun route.

Target:

	export CONTROL_TUN_IP="192.168.50.1"
	export TARGET_TUN_IP="192.168.50.2"
	export TARGET_TUN_IF="tun0"
	export TARGET_ETH_IF="ens33"

	echo 1 >/proc/sys/net/ipv4/ip_forward
	iptables -t nat -A POSTROUTING -s $TARGET_TUN_IP -o $TARGET_ETH_IF -j MASQUERADE
	ip addr add $TARGET_TUN_IP dev $TARGET_TUN_IF peer $CONTROL_TUN_IP
	ip link set $TARGET_TUN_IF up

Control:

	export CONTROL_TUN_IF="tun0"
	export CONTROL_TUN_IP="192.168.50.1"
	export TARGET_TUN_IP="192.168.50.2"
	export TARGET_ETH_NET="10.5.120.0/24"
	export CONTROL_ETH_IF="eth0"

	ip addr add $CONTROL_TUN_IP dev $CONTROL_TUN_IF peer $TARGET_TUN_IP
	ip link set $CONTROL_TUN_IF up
	ip route add $TARGET_ETH_NET via $CONTROL_TUN_IP

### Setting up a Tap bridge.

Target:

	export TARGET_BRIDGE_IF="br0"
	export TARGET_TAP_IF="tap0"
	export TARGET_SECOND_ETH_IF="ens37"

	ip link add $TARGET_BRIDGE_IF type bridge
	ip link set $TARGET_BRIDGE_IF up
	ip link set $TARGET_TAP_IF up
	ip link set $TARGET_TAP_IF master $TARGET_BRIDGE_IF
	ip link set $TARGET_SECOND_ETH_IF up
	ip link set $TARGET_SECOND_ETH_IF master $TARGET_BRIDGE_IF

Control:

	export CONTROL_TAP_IF="tap0"

	dhclient $CONTROL_TAP_IF

## Further Reading

- [Arch Linux: Network Bridge](https://wiki.archlinux.org/index.php/Network_bridge)
- [Arch Linux: Internet Sharing](https://wiki.archlinux.org/index.php/Internet_sharing)

