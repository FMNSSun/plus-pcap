package main

import "fmt"
import "github.com/google/gopacket/pcap"
import "github.com/google/gopacket"
import "github.com/google/gopacket/layers"
import "flag"
import "encoding/json"

var path = flag.String("pcap-file", "", "Path to a PCAP file.")
var live = flag.Bool("live", false, "Live capture? If set to true capture packets from specified iface.")
var snaplen = flag.Int("snaplen", 8192, "Snaplen: Max length of captured payload per packet.")
var iface = flag.String("iface", "eth0", "Interface to use.")
var plusOnly = flag.Bool("plus-only", true, "Only plus? If set to true ignore non-PLUS packets.")
var dumpType = flag.String("dump-type", "gopacket", "Dump packets as JSON? Available: gopacket, json")
var prettyJson = flag.Bool("pretty-json", false, "Pretty print JSON?")

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


type dumpLayer struct {
	LayerName string
	Layer gopacket.Layer
}

func dumpPacket(packet gopacket.Packet) {
	switch *dumpType {
		case "json":
			dumpLayers := []dumpLayer{}
			for _, layer := range packet.Layers() {
				it := dumpLayer { LayerName : gopacket.GetLayerTypeMetadata(int(layer.LayerType())).Name,
									   Layer : layer }
				dumpLayers = append(dumpLayers, it)
			}

			if !*prettyJson {
				str, _ := json.Marshal(dumpLayers)
				fmt.Println(string(str))
			} else {
				str, _ := json.MarshalIndent(dumpLayers, "", "  ")
				fmt.Println(string(str))
			}

		case "gopacket":
			fmt.Println(packet)
	}
}

func runWithPacketSource(packetSource *gopacket.PacketSource) {
	for packet := range packetSource.Packets() {
		if *plusOnly {
			packetLayers := packet.Layers()

			if len(packetLayers) == 0 {
				continue
			}

			var plusLayer gopacket.Layer = nil

			for _, layer := range packetLayers {
				if layer.LayerType() == layers.LayerTypePLUS {
					plusLayer = layer
					break
				}

				
			}

			if plusLayer == nil {
				continue
			}

			dumpPacket(packet)
		} else {
			dumpPacket(packet)
		}
	}
}
