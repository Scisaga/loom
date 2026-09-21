package main

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildReviewComparesExactDecodedPixels(t *testing.T) {
	root := t.TempDir()
	writeTestPNG(t, filepath.Join(root, "android", "baseline", "same.png"), 2, 2, color.NRGBA{R: 12, G: 34, B: 56, A: 255})
	writeTestPNG(t, filepath.Join(root, "android", "current", "same.png"), 2, 2, color.NRGBA{R: 12, G: 34, B: 56, A: 255})
	writeTestPNG(t, filepath.Join(root, "android", "baseline", "changed.png"), 2, 2, color.NRGBA{R: 12, G: 34, B: 56, A: 255})
	changed := image.NewNRGBA(image.Rect(0, 0, 2, 2))
	fillTestImage(changed, color.NRGBA{R: 12, G: 34, B: 56, A: 255})
	changed.SetNRGBA(1, 1, color.NRGBA{R: 13, G: 34, B: 56, A: 255})
	writeTestImage(t, filepath.Join(root, "android", "current", "changed.png"), changed)

	summary, err := buildReview(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Scenes != 2 || summary.Changed != 1 || summary.Missing != 0 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if _, err := os.Stat(filepath.Join(root, "android", "diff", "changed.png")); err != nil {
		t.Fatal(err)
	}
	if _, err := buildReview(root, true); err == nil || !strings.Contains(err.Error(), "1 changed") {
		t.Fatalf("strict comparison did not reject a pixel difference: %v", err)
	}
}

func TestBuildReviewRejectsMissingAndChangedSize(t *testing.T) {
	root := t.TempDir()
	writeTestPNG(t, filepath.Join(root, "windows", "baseline", "missing-current.png"), 2, 2, color.NRGBA{A: 255})
	writeTestPNG(t, filepath.Join(root, "windows", "current", "missing-baseline.png"), 2, 2, color.NRGBA{A: 255})
	writeTestPNG(t, filepath.Join(root, "windows", "baseline", "size.png"), 2, 2, color.NRGBA{A: 255})
	writeTestPNG(t, filepath.Join(root, "windows", "current", "size.png"), 3, 2, color.NRGBA{A: 255})

	summary, err := buildReview(root, false)
	if err == nil || !strings.Contains(err.Error(), "2 missing") {
		t.Fatalf("preview did not reject an incomplete scene set: %v", err)
	}
	if summary.Scenes != 3 || summary.Changed != 1 || summary.Missing != 2 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
}

func TestPreviewShowsSizeChangeAndStrictVerificationRejectsIt(t *testing.T) {
	root := t.TempDir()
	writeTestPNG(t, filepath.Join(root, "android", "baseline", "size.png"), 2, 2, color.NRGBA{A: 255})
	writeTestPNG(t, filepath.Join(root, "android", "current", "size.png"), 3, 2, color.NRGBA{A: 255})

	summary, err := buildReviewPlatforms(root, false, []string{"android"})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Changed != 1 || summary.Missing != 0 {
		t.Fatalf("unexpected size-change summary: %+v", summary)
	}
	if _, err := buildReviewPlatforms(root, true, []string{"android"}); err == nil || !strings.Contains(err.Error(), "1 changed") {
		t.Fatalf("strict verification did not reject a size change: %v", err)
	}
}

func TestBuildReviewIsStableAndEscapesGalleryData(t *testing.T) {
	root := t.TempDir()
	name := "nested/a<b"
	writeTestPNG(t, filepath.Join(root, "android", "baseline", name+".png"), 1, 1, color.NRGBA{R: 1, A: 255})
	writeTestPNG(t, filepath.Join(root, "android", "current", name+".png"), 1, 1, color.NRGBA{R: 1, A: 255})
	metadata := []byte("{\"renderer\":\"</script><b>unsafe</b>\"}\n")
	if err := os.WriteFile(filepath.Join(root, "android", "metadata.json"), metadata, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := buildReview(root, false); err != nil {
		t.Fatal(err)
	}
	firstManifest, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := buildReview(root, false); err != nil {
		t.Fatal(err)
	}
	secondManifest, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(firstManifest) != string(secondManifest) {
		t.Fatal("manifest ordering or generation is not deterministic")
	}
	page, err := os.ReadFile(filepath.Join(root, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(page), "</script><b>unsafe") || !strings.Contains(string(page), `\u003c/script\u003e`) {
		t.Fatal("gallery data was not safely encoded")
	}
}

func TestSelectedPlatformsRejectsUnknownValue(t *testing.T) {
	platforms, err := selectedPlatforms("android")
	if err != nil || len(platforms) != 1 || platforms[0] != "android" {
		t.Fatalf("unexpected Android platform selection: %v, %v", platforms, err)
	}
	if _, err := selectedPlatforms("desktop"); err == nil {
		t.Fatal("unknown platform was accepted")
	}
}

func writeTestPNG(t *testing.T, path string, width, height int, value color.NRGBA) {
	t.Helper()
	picture := image.NewNRGBA(image.Rect(0, 0, width, height))
	fillTestImage(picture, value)
	writeTestImage(t, path, picture)
}

func fillTestImage(picture *image.NRGBA, value color.NRGBA) {
	for y := picture.Bounds().Min.Y; y < picture.Bounds().Max.Y; y++ {
		for x := picture.Bounds().Min.X; x < picture.Bounds().Max.X; x++ {
			picture.SetNRGBA(x, y, value)
		}
	}
}

func writeTestImage(t *testing.T, path string, picture image.Image) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(file, picture); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
