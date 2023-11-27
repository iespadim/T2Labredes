package main

import (
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Sniffer interface {
	// Open and configure the network interface
	Open(config *Config) error

	// Close the interface
	Close()

	// Read the next packet from the interface
	ReadPacket() (data []byte, ci gopacket.CaptureInfo, err error)
}

// Layers that we care about decoding
var (
	eth     layers.Ethernet
	ip      layers.IPv4
	tcp     layers.TCP
	udp     layers.UDP
	icmp    layers.ICMPv4
	dns     layers.DNS
	payload gopacket.Payload
)

// Listen in an infinite loop for new packets
func Listen(iface string, networkStats *NetworkStatistics, config *Config) error {
	// Array to store which layers were decoded
	decoded := []gopacket.LayerType{}

	// Faster, predefined layer parser that doesn't make copies of the layer slices
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&eth,
		&ip,
		&tcp,
		&udp,
		&icmp,
		&dns,
		&payload)

	// Infinite loop that reads incoming packets
	for {
		data, ci, err := config.sniffer.ReadPacket()
		if err != nil {
			log.Printf("Error getting packet: %v %s", err, ci)
			continue
		}
		err = parser.DecodeLayers(data, &decoded)
		if err != nil {
			log.Printf("Error decodificando packet: %v", err)
			continue
		}
		if len(decoded) == 0 {
			log.Print("Packet contained no valid layers")
			continue
		}

		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeIPv4:
				networkStats.ipv4Count++
			case layers.LayerTypeIPv6:
				networkStats.ipv6Count++
			case layers.LayerTypeICMPv4:
				networkStats.icmpv4Count++
			case layers.LayerTypeICMPv6:
				networkStats.icmpv6Count++
			case layers.LayerTypeARP:
				networkStats.arpRequestCount++
				networkStats.arpReplyCount++
			}
		}
	}

	return nil
}
