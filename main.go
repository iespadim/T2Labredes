package main

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Quantidade de pacotes IPv4
// - Quantidade de pacotes ICMP
// - Quantidade de pacotes IPv6
// - Quantidade de pacotes ICMPv6
type NetworkStatistics struct {
	icmpv4Count     int
	icmpv6Count     int
	ipv4Count       int
	ipv6Count       int
	arpRequestCount int
	arpReplyCount   int
}

func main() {
	// Crie uma instância de NetworkStatistics
	networkStats := &NetworkStatistics{}

	// Inicie a goroutine para ouvir pacotes
	go printCliUI(networkStats)

	go ListenAll(networkStats)

	// Adicione qualquer outra lógica principal aqui

	// Mantenha o programa em execução
	select {}
}

func processPacket(packet gopacket.Packet, networkStats *NetworkStatistics) {
	networkLayer := packet.NetworkLayer()
	if networkLayer != nil {
		switch networkLayer.LayerType() {
		case layers.LayerTypeIPv4:
			networkStats.ipv4Count++
		case layers.LayerTypeIPv6:
			networkStats.ipv6Count++
		case layers.LayerTypeICMPv4:
			networkStats.icmpv4Count++
		case layers.LayerTypeICMPv6:
			networkStats.icmpv6Count++
		case layers.LayerTypeARP:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			arp, _ := arpLayer.(*layers.ARP)
			if arp.Operation == 1 {
				networkStats.arpRequestCount++
			}
			if arp.Operation == 2 {
				networkStats.arpReplyCount++
			}
		}
	}
}

func printCliUI(networkStats *NetworkStatistics) {
	//will print and refresh values on screen of network statistics from the networkStats struct
	for {
		fmt.Println("\033[H\033[2J")
		fmt.Println("ICMPv4: ", networkStats.icmpv4Count)
		fmt.Println("ICMPv6: ", networkStats.icmpv6Count)
		fmt.Println("IPv4: ", networkStats.ipv4Count)
		fmt.Println("IPv6: ", networkStats.ipv6Count)
		fmt.Println("ARP: ", networkStats.arpRequestCount)
		fmt.Println("ARP: ", networkStats.arpReplyCount)

		time.Sleep(1 * time.Second)
	}

}
