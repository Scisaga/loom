package clientruntime

import (
	"fmt"
	"strings"
	"testing"
)

func validWindowsConfig(logLevel string) string {
	return fmt.Sprintf(`{
  "log": {"level": %q},
  "dns": {"servers": [{"tag":"dns0","address":"1.1.1.1","detour":"dns-out"}]},
  "inbounds": [
    {"type":"tun","tag":"tun-in","address":["172.19.0.1/30"],"auto_route":true,"stack":"system"},
    {"type":"mixed","tag":"in-1080","listen":"127.0.0.1","listen_port":1080}
  ],
  "outbounds": [
    {"type":"direct","tag":"dns-out"},
    {"type":"hysteria2","tag":"cand:auto:edge","server":"edge.example.com","server_port":443,"password":"${secret:vault:cred/win01}","tls":{"enabled":true,"server_name":"edge.node.internal","certificate_path":"C:\\ProgramData\\Loom\\tls\\ca.crt","alpn":["h3"]}},
    {"type":"selector","tag":"decl:auto","outbounds":["cand:auto:edge"],"default":"cand:auto:edge"},
    {"type":"block","tag":"block"}
  ],
  "route": {"rules":[{"inbound":["tun-in","in-1080"],"outbound":"decl:auto"}],"final":"block"},
  "experimental": {"clash_api":{"external_controller":"127.0.0.1:61800","secret":"${secret:api/win01}"}}
}`, logLevel)
}

func pathPlanFixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	body := strings.NewReplacer("${secret:api/win01}", "demo-api", "${secret:vault:cred/win01}", "demo-secret").
		Replace(validWindowsConfig("warn"))
	return []byte(body), nil
}
