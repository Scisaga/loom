package loomcore

import (
	"testing"
	"time"

	"loom/internal/clientadapter"
)

func TestAndroidMeasurementCheckUsesMeasurementPeriod(t *testing.T) {
	interval := time.Duration(AndroidMeasurementCheckIntervalMillis()) * time.Millisecond
	timing := clientadapter.DefaultMeasurementTiming
	if interval <= 0 || interval != timing.RecoveryPeriod() {
		t.Fatal("Android check differs from the measurement recovery period")
	}
}
