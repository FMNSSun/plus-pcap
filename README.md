# plus-pcap

Inspect PLUS packets in PCAP files or live.

# Example Usages

Read a PCAP file with PLUS packets:

```
./plus-pcap --pcap-file ~/MAMI/plus-pdbg.pcap -dump-type=json
```

Live:

```
sudo ./plus-pcap -iface=lo -live -plus-only=true -dump-type=json
```
