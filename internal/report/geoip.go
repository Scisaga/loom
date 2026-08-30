package report

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"loom/internal/model"
)

const (
	defaultGeoIPProvider = "ipwho.is"
	maxGeoIPResponse     = 16 << 10
)

type geoIPLocation struct {
	Country, City, Evidence string
}

type ipWhoIsResponse struct {
	IP          string `json:"ip"`
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	CountryCode string `json:"country_code"`
	City        string `json:"city"`
}

// lookupIPWhoIs asks only for the fields used to prepare an operator-editable
// suggestion. The answer is never endpoint evidence and a failure must never
// stop enrollment.
func lookupIPWhoIs(ctx context.Context, client *http.Client, rawIP string) (geoIPLocation, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(rawIP))
	if err != nil {
		return geoIPLocation{}, fmt.Errorf("invalid lookup IP %q", rawIP)
	}
	ip = ip.Unmap()
	if !isPublicGlobalUnicast(ip) {
		return geoIPLocation{}, fmt.Errorf("lookup IP %s is not public global-unicast", ip)
	}
	if client == nil {
		return geoIPLocation{}, fmt.Errorf("HTTP client is unavailable")
	}

	query := url.Values{"fields": {"success,message,ip,country_code,city"}}
	endpoint := "https://ipwho.is/" + ip.String() + "?" + query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return geoIPLocation{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "loom-control/geoip")
	resp, err := client.Do(req)
	if err != nil {
		return geoIPLocation{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return geoIPLocation{}, fmt.Errorf("%s returned HTTP %d", defaultGeoIPProvider, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGeoIPResponse+1))
	if err != nil {
		return geoIPLocation{}, err
	}
	if len(body) > maxGeoIPResponse {
		return geoIPLocation{}, fmt.Errorf("%s response exceeds %d bytes", defaultGeoIPProvider, maxGeoIPResponse)
	}
	var decoded ipWhoIsResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return geoIPLocation{}, fmt.Errorf("decode %s response: %w", defaultGeoIPProvider, err)
	}
	if !decoded.Success {
		message := strings.TrimSpace(decoded.Message)
		if message == "" {
			message = "lookup was unsuccessful"
		}
		return geoIPLocation{}, fmt.Errorf("%s: %s", defaultGeoIPProvider, message)
	}
	answerIP, err := netip.ParseAddr(strings.TrimSpace(decoded.IP))
	if err != nil || answerIP.Unmap() != ip {
		return geoIPLocation{}, fmt.Errorf("%s response IP %q does not match %s", defaultGeoIPProvider, decoded.IP, ip)
	}
	country := strings.ToUpper(strings.TrimSpace(decoded.CountryCode))
	if country != "" && !model.ValidCountryCode(country) {
		return geoIPLocation{}, fmt.Errorf("%s returned invalid country code %q", defaultGeoIPProvider, decoded.CountryCode)
	}
	city := strings.TrimSpace(decoded.City)
	if !utf8.ValidString(city) || len(city) > 256 || strings.IndexFunc(city, unicode.IsControl) >= 0 {
		return geoIPLocation{}, fmt.Errorf("%s returned an invalid city", defaultGeoIPProvider)
	}
	if country == "" && city == "" {
		return geoIPLocation{}, fmt.Errorf("%s returned no country or city", defaultGeoIPProvider)
	}
	return geoIPLocation{
		Country: country,
		City:    city,
		Evidence: fmt.Sprintf(
			"GeoIP suggestion from %s for public endpoint address %s; approximate and not trusted endpoint or location evidence.",
			defaultGeoIPProvider, ip),
	}, nil
}

func firstEndpointAddress(resolution string) (string, error) {
	first, _, _ := strings.Cut(strings.TrimSpace(resolution), ",")
	ip, err := netip.ParseAddr(strings.TrimSpace(first))
	if err != nil {
		return "", fmt.Errorf("endpoint resolution has no usable public IP")
	}
	ip = ip.Unmap()
	if !isPublicGlobalUnicast(ip) {
		return "", fmt.Errorf("endpoint resolution address %s is not public global-unicast", ip)
	}
	return ip.String(), nil
}
