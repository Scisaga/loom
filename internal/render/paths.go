package render

// ReportPort is retained as the read-only address of already deployed server
// telemetry. The old report producer is deliberately no longer rendered.
const ReportPort = 61802

// ManifestPath is the installed server bundle manifest consumed by the generic
// apply and drift-reading paths. It is not a Linux client state store.
const ManifestPath = "/etc/loom/report/manifest.json"
