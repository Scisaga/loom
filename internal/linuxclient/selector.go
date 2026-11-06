package linuxclient

import (
	"context"
	"loom/internal/clientadapter"
)

type Selector = clientadapter.Selector
type HTTPSelector = clientadapter.HTTPSelector

func NewHTTPSelector(config string) (*HTTPSelector, error) {
	return clientadapter.NewHTTPSelector(config)
}
func waitSelector(ctx context.Context, selector Selector, scopes []string) error {
	return clientadapter.WaitSelector(ctx, selector, scopes)
}
func applySelections(ctx context.Context, selector Selector, desired map[string]string) (map[string]string, error) {
	return clientadapter.ApplySelections(ctx, selector, desired)
}
