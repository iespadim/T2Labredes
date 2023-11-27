package main

import (
	"fmt"
	"time"
)

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
		fmt.Println("P/s", networkStats.packetsPerSecond)
		fmt.Println("  ", networkStats.DDos)
		fmt.Println("  ", networkStats.synFlood)

		time.Sleep(1 * time.Second)
	}
}
