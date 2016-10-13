
# Reverse VPNs with _revsh_.

### What is a reverse VPN and how can I use _revsh_ to get one?

A [VPN](https://en.wikipedia.org/wiki/Virtual_private_network) is a mechanism that automatically routes network traffic for a user across a [tunnel](https://en.wikipedia.org/wiki/Tunneling_protocol) in a way that gives the appearance to the user that their machine is actually on the remote network. This allows for the seamless interaction of local network tools with remote hosts / services. A reverse VPN is simply a VPN that opens the initial connection back out to the user. This is related to the idea and use of a [reverse shell](https://en.wikipedia.org/wiki/Shell_shoveling).

_revsh_ is a network tool that allows for a reverse connection back to the user followed by arbitrary data tunneling. By leveraging tun/tap devices native to Linux and FreeBSD, it is able to forward raw IP packets / Ethernet frames across its tunnel. This allows for the experience of a VPN.

### What are Tun / Tap devices?

[Tun / Tap](https://en.wikipedia.org/wiki/TUN/TAP) devices are virtual network cards. They are fully featured and supported kernel network devices that aren't attached to a physical card. Rather, when the kernel decides to route a packet / frame down a tun / tap device, it comes out of the application end of the driver and is delivered to the attached application. In this case the attached application is _revsh_. Tun devices handle forwarding of raw IP packets. Tap devices handle forwarding of raw Ethernet frames. 

In addition to _revsh_, both [ssh](https://www.openssh.com/) and [openvpn](https://openvpn.net/) offer up tun / tap support. All operators should learn to leverage this feature across each of these tools to ensure maximum flexibility.

### When would I use one instead of the other?

- A tap connection opens up the entire range of [layer two attacks](https://en.wikipedia.org/wiki/ARP_spoofing) to the operator. A tun connection is restricted to layer 3 of the [OSI model](https://en.wikipedia.org/wiki/OSI_model) and above.
- Because there is no additional layer 2 overhead (discovery / handling), tun connections are marginally faster. (This is debatable and based on theory. I haven't seen hard data yet.)
- A tap connection will require a second ethernet device on the remote host. This is because upon connecting a network device to a bridge it *will* loose its IP address / drop it's connections. In a situation where the remote target host only has one ethernet device, that is the device your tunnel is connected through. If you add it to a bridge your entire connection will be lost.
- Tap bridges are easier to setup / manage. (This is debatable and is only a statement of my personal preference.)

## Examples

The below examples are broken up into command segments outlining the commands needed to be run on the target and control hosts. The order they appear below are the order they need to be entered to the appropriate hosts. Further, the command segments have been separated into two sections of "variables that define the environment" and "commands". You should only need to update the variables to suit your needs before copy/pasting the command segments below into your respective terminals.

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
- [Hacks by Brandon: Layer 2 VPN’s using SSH](https://la11111.wordpress.com/2012/09/24/layer-2-vpns-using-ssh/)
- [OpenVPN: Bridging vs. routing](https://community.openvpn.net/openvpn/wiki/BridgingAndRouting)
