# broadcast-relay [![Build Status](https://travis-ci.org/Golit/broadcast-relay.svg?branch=master)](https://travis-ci.org/Golit/broadcast-relay)

This utility will relay limited broadcasts (255.255.255.255) from an interface to another interface (or on the same interface). You can use this utility for VPN servers to forward limited broadcast. The interface needs to be in bridged mode.


## Using on Debain Jessie
Install dependencies
```sh
apt install libnl-3-200 libnl-genl-3-200 dbus
```

### Setup
Download the utility and install the systemd service.
```sh
URI=$(curl -s https://api.github.com/repos/Golit/broadcast-relay/releases | grep browser_download_url | head -n 1 | cut -d '"' -f 4)
curl -L -o /usr/local/bin/broadcast-relay $URI
chmod +x /usr/local/bin/broadcast-relay
cat > /etc/systemd/system/broadcast-relay@.service <<EOF
[Unit]
Description=Relay For Limited Broadcasts On Interface %I
After=network.target system-openvpn.slice

[Service]
Type=simple
ExecStart=/usr/local/bin/broadcast-relay --interface-in %i --interface-out %i

[Install]
WantedBy=multi-user.target
EOF
systemctl enable broadcast-relay@tap0
systemctl start broadcast-relay@tap0
```

### Usage
```sh
broadcast-relay [-i <interface with broadcasts>] [-o <interface where to relay broadcasts>] [-h] [-l <loglevel>]
broadcast-relay --interface-in tap0 --interface-out tap0
```

## Contribution
Contributions are welcome.

## References for developer

### libpcap
<http://www.tcpdump.org/pcap.html>

<http://eecs.wsu.edu/~sshaikot/docs/lbpcap/libpcap-tutorial.pdf>

### getopt
<https://linux.die.net/man/3/getopt_long>

### raw sockets
<http://opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/>

<http://www.pdbuchan.com/rawsock/rawsock.html>
