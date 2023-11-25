package main

import (
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// ListenAll é uma função que ouve pacotes
func ListenAll(networkStats *NetworkStatistics) {
	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		// Processar e analisar o pacote aqui
		// Encaminhar o pacote para a classe NetworkStatistics
		processPacket(packet, networkStats)
	}
}
