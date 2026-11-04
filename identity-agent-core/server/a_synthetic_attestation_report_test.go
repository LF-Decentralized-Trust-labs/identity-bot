package server

import "identity-agent-core/secureenclave"

// A report shaped the way the hardware produces one, so the checks are
// exercised rather than described.
func syntheticReport(bindTo string, measurement byte) []byte {
	raw := make([]byte, secureenclave.ReportSize)
	copy(raw[0x50:], secureenclave.BindReportData(bindTo)) // REPORT_DATA
	for i := 0; i < secureenclave.MeasurementSize; i++ {
		raw[0x90+i] = measurement
	}
	for i := 0; i < secureenclave.ChipIDSize; i++ {
		raw[0x1A0+i] = 0x5A // CHIP_ID must not be masked
	}
	raw[0x2A0] = 0x01 // a signature must be present
	return raw
}
