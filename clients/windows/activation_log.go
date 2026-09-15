package main

import (
	"log"
	"time"
)

const dataPlaneStartupGrace = 2 * time.Second

func logActivation(message string, activation *clientActivation) {
	if activation == nil {
		return
	}
	configID := activation.Version.ConfigSHA256
	if len(configID) > 12 {
		configID = configID[:12]
	}
	slotID := activation.SlotID
	if len(slotID) > 12 {
		slotID = slotID[:12]
	}
	log.Printf("%s snapshot=%s config=%s slot=%s profile=%s", message,
		activation.Version.Snapshot, configID, slotID, activation.Profile)
}
