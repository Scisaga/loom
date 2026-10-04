package clientruntime

import "testing"

func validWindowsConfig(_ string) string {
	return `{"inbounds":[{"type":"tun","tag":"tun-in","auto_route":true}],"outbounds":[{"type":"block","tag":"reject"},{"type":"direct","tag":"demo-candidate"},{"type":"selector","tag":"service:demo-service","outbounds":["demo-candidate"],"default":"demo-candidate"}],"route":{"rules":[{"type":"logical","mode":"or","rules":[{"domain":["demo-service.example"]}],"outbound":"service:demo-service"}],"final":"reject"},"experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"demo-api"}}}`
}
func pathPlanFixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	return []byte(validWindowsConfig("")), nil
}
