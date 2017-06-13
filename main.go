package main

import "os"
import "fmt"
import "github.com/google/gopacket/pcap"
import "github.com/google/gopacket"

func main() {
	if handle, err := pcap.OpenOffline(os.Args[1]); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			fmt.Println(packet)
		}
	}
}
