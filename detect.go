package main

import "time"

// Adicione métodos de detecção de ataque à struct NetworkStatistics
func (ns *NetworkStatistics) detectDosAttack() bool {
	// Regra: Se o número total de pacotes exceder um limite em um curto período de tempo (5 segundos), considere como um ataque DoS.
	maxPacketsPerSecond := 100
	dosAttackThreshold := 5.0 // em segundos

	currentTime := time.Now()
	elapsedTime := currentTime.Sub(ns.lastSynTime).Seconds()

	// Verifique se o tempo decorrido é maior que o limite para calcular a taxa corretamente
	if elapsedTime >= dosAttackThreshold {
		packetsPerSecond := float64(ns.GetTotalPackets()) / elapsedTime
		intPacketsPerSecond := int(packetsPerSecond)

		ns.packetsPerSecond = float64(intPacketsPerSecond)
		if packetsPerSecond > float64(maxPacketsPerSecond) {
			return true
		}
	}

	return false
}

func (ns *NetworkStatistics) detectSynFloodAttack() bool {
	// Regra: Se a taxa de pacotes SYN for anormalmente alta, considere como um ataque SYN Flood.
	maxSynRate := 10 // Ajuste conforme necessário

	currentTime := time.Now()
	synRate := float64(ns.synCount) / currentTime.Sub(ns.lastSynTime).Seconds()

	if synRate > float64(maxSynRate) {
		return true
	}
	return false
}
