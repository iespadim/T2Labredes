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
	synCount        int
	lastSynTime     time.Time
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
		case layers.LayerTypeTCP:
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			tcp, _ := tcpLayer.(*layers.TCP)
			if tcp.SYN {
				networkStats.synCount++
			}
		}
	}

	// Verifique e imprima estatísticas de ataque
	if networkStats.detectDosAttack() {
		fmt.Println("Ataque DoS detectado!")

	}

	if networkStats.detectSynFloodAttack() {
		fmt.Println("Ataque SYN Flood detectado!")
		// Adicione lógica adicional conforme necessário
	}
}

// Adicione métodos de detecção de ataque à struct NetworkStatistics
func (ns *NetworkStatistics) detectDosAttack() bool {
	// Regra: Se o número total de pacotes exceder um limite em um curto período de tempo, considere como um ataque DoS.
	maxPacketsPerSecond := 1000

	currentTime := time.Now()
	packetsPerSecond := float64(ns.getTotalPackets()) / currentTime.Sub(ns.lastSynTime).Seconds()

	if packetsPerSecond > float64(maxPacketsPerSecond) {
		return true
	}
	return false
}

func (ns *NetworkStatistics) detectSynFloodAttack() bool {
	// Regra: Se a taxa de pacotes SYN for anormalmente alta, considere como um ataque SYN Flood.
	maxSynRate := 100 // Ajuste conforme necessário

	currentTime := time.Now()
	synRate := float64(ns.synCount) / currentTime.Sub(ns.lastSynTime).Seconds()

	if synRate > float64(maxSynRate) {
		return true
	}
	return false
}

// Método auxiliar para obter o número total de pacotes
func (ns *NetworkStatistics) getTotalPackets() int {
	return ns.icmpv4Count + ns.icmpv6Count + ns.ipv4Count + ns.ipv6Count + ns.arpRequestCount + ns.arpReplyCount + ns.synCount
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
