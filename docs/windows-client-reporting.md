# Windows client reporting

This historical document previously described the removed public
`/loom-client/report` producer, P-256 certificate identity, periodic Agent
measurements, and snapshot generation reporting. None of those values or routes
are part of the rebuilt Windows client.

The current contract is defined by:

- [Client runtime model](rebuild/client-runtime-model.md), including real
  Observation, selector-readback Selection, DPAPI persistence, and failure
  semantics;
- [Enrollment endpoint model](rebuild/enrollment-endpoint-model.md), including
  the authenticated private device tunnel and signed `DeviceReport` wire;
- [Windows client README](../clients/windows/README.md), for HostAdapter and
  delivery behavior.

A report is sent only through the private authenticated device tunnel, signed
by the profile's Ed25519 identity, after the runtime has actually applied a
candidate and read the selector back. It contains the current Selection and
real TCP/TLS and UDP/DNS Observations. It does not derive a public report URL,
use a certificate attachment, run a periodic health scheduler, or accept public
observations in the response.
