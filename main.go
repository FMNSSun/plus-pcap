package main

import "fmt"
import "github.com/google/gopacket/pcap"
import "github.com/google/gopacket"
import "github.com/google/gopacket/layers"
import "flag"
import "net"
import "encoding/json"

var path = flag.String("pcap-file", "", "Path to a PCAP file.")
var live = flag.Bool("live", false, "Live capture? If set to true capture packets from specified iface.")
var snaplen = flag.Int("snaplen", 8192, "Snaplen: Max length of captured payload per packet.")
var iface = flag.String("iface", "eth0", "Interface to use.")
var plusOnly = flag.Bool("plus-only", true, "Only plus? If set to true ignore non-PLUS packets.")
var dumpType = flag.String("dump-type", "gopacket", "Dump PLUS packets as JSON? Available: gopacket, json, json-payload (include payload). json* requires PLUS only!")

func main() {
	flag.Parse()

	if *path == "" && *live == false {
		flag.Usage()
		return
	}

	if *dumpType != "gopacket" && !*plusOnly {
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

type metainfo struct {
	DstIP net.IP
	SrcIP net.IP
	DstPort uint16
	SrcPort uint16
}

var jsonDumpStr = "{\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"src_port\":%d,\"dst_port\":%d,\"cat\":%d,\"psn\":%d,\"pse\":%d,\"magic\":%d,\"pcf_integrity\":%d,\"pcf_len\":%d,\"pcf_type\":%d,\"pcf_value\":%s,\"flags\":{\"xflag\":%t,\"sflag\":%t,\"rflag\":%t,\"lflag\":%t},\"payload\":%s}\n"

func dumpJSONPLUS(packet gopacket.Packet, plusLayer gopacket.Layer, meta metainfo, showPayload bool) {
	switch plusLayer.(type) {
		case *layers.PLUS:
			pl := plusLayer.(*layers.PLUS)

			var payload []byte = nil

			if showPayload {
				payload = plusLayer.LayerPayload()
			}

			payloadStr, _ := json.Marshal(payload)
			pcfValueStr, _ := json.Marshal(pl.PCFValue)
			
			fmt.Printf(jsonDumpStr, meta.SrcIP.String(), meta.DstIP.String(),
				meta.SrcPort, meta.DstPort,
				pl.CAT, pl.PSN, pl.PSE, pl.Magic,
				pl.PCFIntegrity, pl.PCFLen, pl.PCFType, pcfValueStr,
				pl.XFlag, pl.SFlag, pl.RFlag, pl.LFlag, payloadStr)
	}
}

func dumpPLUS(packet gopacket.Packet, plusLayer gopacket.Layer, meta metainfo) {
	switch *dumpType {
		case "gopacket":
			fmt.Println(packet)
		case "json":
			dumpJSONPLUS(packet, plusLayer, meta, false)
		case "json-payload":
			dumpJSONPLUS(packet, plusLayer, meta, true)
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
			var srcIP net.IP = nil
			var dstIP net.IP = nil
			var srcPort = uint16(0)
			var dstPort = uint16(0)

			for _, layer := range packetLayers {
				if layer.LayerType() == layers.LayerTypePLUS {
					plusLayer = layer
					break
				}

				if layer.LayerType() == layers.LayerTypeIPv4 {
					layer := layer.(*layers.IPv4)
					srcIP = layer.SrcIP
					dstIP = layer.DstIP
				}

				if layer.LayerType() == layers.LayerTypeUDP {
					layer := layer.(*layers.UDP)
					srcPort = uint16(layer.SrcPort)
					dstPort = uint16(layer.DstPort)
				}
			}

			if plusLayer == nil {
				continue
			}

			dumpPLUS(packet, plusLayer, metainfo { DstIP : dstIP, SrcIP : srcIP, SrcPort : srcPort, DstPort : dstPort })
		} else {
			fmt.Println(packet)
		}
	}
}
