package main

import "fmt"
import "github.com/google/gopacket/pcap"
import "github.com/google/gopacket"
import "github.com/google/gopacket/layers"
import "flag"

var path = flag.String("pcap-file", "", "Path to a PCAP file.")
var live = flag.Bool("live", false, "Live capture? If set to true capture packets from specified iface.")
var snaplen = flag.Int("snaplen", 8129, "Snaplen: Max length of captured payload per packet.")
var iface = flag.String("iface", "eth0", "Interface to use.")
var plusOnly = flag.Bool("plus-only", true, "Only plus? If set to true ignore non-PLUS packets.")

func main() {
	flag.Parse()

	if *path == "" && *live == false {
		flag.Usage()
		return
	}

	layers.EnableHeuristics()

	if !*live {
		if handle, err := pcap.OpenOffline(*path); err != nil {
			panic(err)
		} else {
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			runWithPacketSource(packetSource)
		}
	} else {
		if handle, err := pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever); err != nil {
			panic(err)
		} else {
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			runWithPacketSource(packetSource)
		}
	}
}

func runWithPacketSource(packetSource *gopacket.PacketSource) {
	for packet := range packetSource.Packets() {
		if *plusOnly {
			packetLayers := packet.Layers()

			if len(packetLayers) == 0 {
				continue
			}

			plusFound := false

			for _, layer := range packetLayers {
				if layer.LayerType() == layers.LayerTypePLUS {
					plusFound = true
					break
				}
			}

			if !plusFound {
				continue
			}
		}

		fmt.Println(packet)
	}
}
