package wire

import (
	"encoding/json"
	"os"
	"testing"
)

type canonicalGolden struct {
	Schema  int `json:"schema"`
	Vectors []struct {
		Name      string `json:"name"`
		Input     string `json:"input"`
		Canonical string `json:"canonical"`
		Domain    string `json:"domain"`
		Hash      string `json:"hash"`
	} `json:"vectors"`
	Malicious []struct {
		Name  string `json:"name"`
		Input string `json:"input"`
	} `json:"malicious"`
}

func TestSharedCanonicalGolden(t *testing.T) {
	body, err := os.ReadFile("../../testdata/wire/v2/canonical.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden canonicalGolden
	if err := json.Unmarshal(body, &golden); err != nil || golden.Schema != 1 {
		t.Fatalf("golden schema: %v", err)
	}
	for _, vector := range golden.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			canonical, err := CanonicalizeStrict([]byte(vector.Input))
			if err != nil || string(canonical) != vector.Canonical {
				t.Fatalf("canonical=%q err=%v", canonical, err)
			}
			hash, err := HashCanonical(vector.Domain, canonical)
			if err != nil || hash != vector.Hash {
				t.Fatalf("hash=%q err=%v", hash, err)
			}
		})
	}
	for _, vector := range golden.Malicious {
		t.Run(vector.Name, func(t *testing.T) {
			if _, err := CanonicalizeStrict([]byte(vector.Input)); err == nil {
				t.Fatal("malicious vector accepted")
			}
		})
	}
}
