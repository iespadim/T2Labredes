package main

import (
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type Config struct {
	iface      string
	pcapOut    string
	enableAF   bool
	pcapFile   *os.File
	pcapWriter *pcapgo.Writer
	sniffer    Sniffer
	isRunning  bool
}

func main() {
	iface := "eth0"
	networkStats := GetStatisticsInstance()
	config := &Config{
		iface:      iface,
		pcapOut:    "out.pcap",
		enableAF:   false,
		pcapFile:   nil,
		pcapWriter: nil,
		sniffer:    nil,
		isRunning:  false,
	}

	// Crie uma instância de NetworkStatistics

	// Inicie a goroutine para ouvir pacotes
	go printCliUI(networkStats)
	go Listen(iface, networkStats, config)

	// Mantenha o programa em execução
	select {}
}

func ProcessPacket(packet gopacket.Packet, networkStats *NetworkStatistics) {
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
		networkStats.DDos = "ataque dos"

	}

	if networkStats.detectSynFloodAttack() {
		fmt.Println("Ataque SYN Flood detectado!")
		networkStats.synFlood = "ataque syn"
	}
}
