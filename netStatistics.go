package main

import "time"

type NetworkStatistics struct {
	icmpv4Count      int
	icmpv6Count      int
	ipv4Count        int
	ipv6Count        int
	arpRequestCount  int
	arpReplyCount    int
	synCount         int
	lastSynTime      time.Time
	packetsPerSecond float64
	DDos             string
	synFlood         string
}

// Método auxiliar para obter o número total de pacotes
func (ns *NetworkStatistics) GetTotalPackets() int {
	return ns.icmpv4Count + ns.icmpv6Count + ns.ipv4Count + ns.ipv6Count + ns.arpRequestCount + ns.arpReplyCount + ns.synCount
}

// singleton
var instance *NetworkStatistics

func GetStatisticsInstance() *NetworkStatistics {
	return instance
}
