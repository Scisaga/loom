package webui

import "strings"

func faviconSVG() string { return faviconAsset }

type eventFilter struct{ Node, Kind, Level, Query string }

func filterEvents(events []EventView, filter eventFilter) []EventView {
	out := make([]EventView, 0, len(events))
	needle := strings.ToLower(filter.Query)
	for _, event := range events {
		if filter.Node != "" && event.Node != filter.Node || filter.Kind != "" && event.Kind != filter.Kind || filter.Level != "" && event.Level != filter.Level {
			continue
		}
		if needle != "" && !strings.Contains(strings.ToLower(strings.Join([]string{event.Node, event.Kind, event.Subject, event.From, event.To, event.Detail}, " ")), needle) {
			continue
		}
		out = append(out, event)
	}
	return out
}

func short(value string) string {
	if len(value) > 12 {
		return value[:12]
	}
	return value
}
