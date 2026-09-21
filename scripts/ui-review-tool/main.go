package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"image"
	"image/color"
	"image/png"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type sceneResult struct {
	Platform      string            `json:"platform"`
	ID            string            `json:"id"`
	Baseline      string            `json:"baseline,omitempty"`
	Current       string            `json:"current,omitempty"`
	Diff          string            `json:"diff,omitempty"`
	Width         int               `json:"width"`
	Height        int               `json:"height"`
	ChangedPixels int               `json:"changed_pixels"`
	TotalPixels   int               `json:"total_pixels"`
	Status        string            `json:"status"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type manifest struct {
	Generation string        `json:"generation"`
	Scenes     []sceneResult `json:"scenes"`
}

type reviewSummary struct {
	Scenes  int
	Changed int
	Missing int
}

func main() {
	root := flag.String("root", "out/ui-review", "review output root")
	strict := flag.Bool("strict", false, "return failure when any visual difference exists")
	platform := flag.String("platform", "all", "platform to compare: android, windows, or all")
	flag.Parse()

	platforms, err := selectedPlatforms(*platform)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	summary, err := buildReviewPlatforms(*root, *strict, platforms)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("UI review: %d scenes, %d changed, %d missing\n", summary.Scenes, summary.Changed, summary.Missing)
}

func buildReview(root string, strict bool) (reviewSummary, error) {
	return buildReviewPlatforms(root, strict, []string{"android", "windows"})
}

func buildReviewPlatforms(root string, strict bool, platforms []string) (reviewSummary, error) {
	var summary reviewSummary
	var scenes []sceneResult
	for _, platform := range platforms {
		platformScenes, err := comparePlatform(root, platform)
		if err != nil {
			return summary, err
		}
		scenes = append(scenes, platformScenes...)
	}
	sort.Slice(scenes, func(i, j int) bool {
		if scenes[i].Platform != scenes[j].Platform {
			return scenes[i].Platform < scenes[j].Platform
		}
		return scenes[i].ID < scenes[j].ID
	})
	for _, scene := range scenes {
		summary.Scenes++
		switch scene.Status {
		case "changed", "size-changed":
			summary.Changed++
		case "missing-baseline", "missing-current":
			summary.Missing++
		}
	}
	if len(scenes) == 0 {
		return summary, errors.New("UI review has no rendered scenes")
	}

	data := manifest{Scenes: scenes}
	hashInput, err := json.Marshal(data.Scenes)
	if err != nil {
		return summary, fmt.Errorf("encode UI review scenes: %w", err)
	}
	hash := sha256.Sum256(hashInput)
	data.Generation = hex.EncodeToString(hash[:])
	encoded, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return summary, fmt.Errorf("encode UI review manifest: %w", err)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return summary, fmt.Errorf("create UI review root: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), append(encoded, '\n'), 0o644); err != nil {
		return summary, fmt.Errorf("write UI review manifest: %w", err)
	}
	if err := writeGallery(filepath.Join(root, "index.html"), data); err != nil {
		return summary, err
	}
	if summary.Missing != 0 {
		return summary, fmt.Errorf("UI review scene set is incomplete: %d missing", summary.Missing)
	}
	if strict && summary.Changed != 0 {
		return summary, fmt.Errorf("UI review differs: %d changed", summary.Changed)
	}
	return summary, nil
}

func selectedPlatforms(platform string) ([]string, error) {
	switch platform {
	case "android":
		return []string{"android"}, nil
	case "windows":
		return []string{"windows"}, nil
	case "all":
		return []string{"android", "windows"}, nil
	default:
		return nil, fmt.Errorf("unsupported UI review platform %q", platform)
	}
}

func comparePlatform(root, platform string) ([]sceneResult, error) {
	platformRoot := filepath.Join(root, platform)
	baselineRoot := filepath.Join(platformRoot, "baseline")
	currentRoot := filepath.Join(platformRoot, "current")
	diffRoot := filepath.Join(platformRoot, "diff")
	baseline, err := pngFiles(baselineRoot)
	if err != nil {
		return nil, err
	}
	current, err := pngFiles(currentRoot)
	if err != nil {
		return nil, err
	}
	if len(baseline) == 0 && len(current) == 0 {
		return nil, nil
	}
	if err := os.RemoveAll(diffRoot); err != nil {
		return nil, fmt.Errorf("clear %s diff output: %w", platform, err)
	}
	if err := os.MkdirAll(diffRoot, 0o755); err != nil {
		return nil, fmt.Errorf("create %s diff output: %w", platform, err)
	}
	metadata, err := readMetadata(filepath.Join(platformRoot, "metadata.json"))
	if err != nil {
		return nil, err
	}
	ids := make(map[string]struct{}, len(baseline)+len(current))
	for id := range baseline {
		ids[id] = struct{}{}
	}
	for id := range current {
		ids[id] = struct{}{}
	}
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)

	results := make([]sceneResult, 0, len(ordered))
	for _, id := range ordered {
		result := sceneResult{Platform: platform, ID: id, Metadata: metadata}
		baselinePath, hasBaseline := baseline[id]
		currentPath, hasCurrent := current[id]
		if hasBaseline {
			result.Baseline = slashRelative(root, baselinePath)
		}
		if hasCurrent {
			result.Current = slashRelative(root, currentPath)
		}
		switch {
		case !hasBaseline:
			result.Status = "missing-baseline"
			bounds, err := imageBounds(currentPath)
			if err != nil {
				return nil, fmt.Errorf("read current %s/%s: %w", platform, id, err)
			}
			result.Width, result.Height = bounds.Dx(), bounds.Dy()
			result.TotalPixels = result.Width * result.Height
		case !hasCurrent:
			result.Status = "missing-current"
			bounds, err := imageBounds(baselinePath)
			if err != nil {
				return nil, fmt.Errorf("read baseline %s/%s: %w", platform, id, err)
			}
			result.Width, result.Height = bounds.Dx(), bounds.Dy()
			result.TotalPixels = result.Width * result.Height
		default:
			diffPath := filepath.Join(diffRoot, filepath.FromSlash(id)+".png")
			comparison, err := compareImages(baselinePath, currentPath, diffPath)
			if err != nil {
				return nil, fmt.Errorf("compare %s/%s: %w", platform, id, err)
			}
			result.Width, result.Height = comparison.width, comparison.height
			result.ChangedPixels, result.TotalPixels = comparison.changed, comparison.total
			result.Status = comparison.status
			result.Diff = slashRelative(root, diffPath)
		}
		results = append(results, result)
	}
	return results, nil
}

func pngFiles(root string) (map[string]string, error) {
	files := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".png") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		id := filepath.ToSlash(strings.TrimSuffix(relative, filepath.Ext(relative)))
		if id == "" || strings.Contains(id, "..") {
			return fmt.Errorf("invalid UI scene path %q", relative)
		}
		if _, exists := files[id]; exists {
			return fmt.Errorf("duplicate UI scene %q", id)
		}
		files[id] = path
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		return files, nil
	}
	return files, err
}

func readMetadata(path string) (map[string]string, error) {
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read UI metadata: %w", err)
	}
	var values map[string]string
	if err := json.Unmarshal(body, &values); err != nil {
		return nil, fmt.Errorf("decode UI metadata %s: %w", path, err)
	}
	return values, nil
}

type comparison struct {
	status         string
	width, height  int
	changed, total int
}

func compareImages(baselinePath, currentPath, diffPath string) (comparison, error) {
	baseline, err := decodePNG(baselinePath)
	if err != nil {
		return comparison{}, err
	}
	current, err := decodePNG(currentPath)
	if err != nil {
		return comparison{}, err
	}
	baselineBounds, currentBounds := baseline.Bounds(), current.Bounds()
	width := max(baselineBounds.Dx(), currentBounds.Dx())
	height := max(baselineBounds.Dy(), currentBounds.Dy())
	diff := image.NewNRGBA(image.Rect(0, 0, width, height))
	result := comparison{status: "unchanged", width: width, height: height, total: width * height}
	if baselineBounds.Dx() != currentBounds.Dx() || baselineBounds.Dy() != currentBounds.Dy() {
		result.status = "size-changed"
	}
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			baselinePixel, baselineOK := pixelAt(baseline, x, y)
			currentPixel, currentOK := pixelAt(current, x, y)
			if !baselineOK || !currentOK || baselinePixel != currentPixel {
				result.changed++
				diff.SetNRGBA(x, y, color.NRGBA{R: 255, B: 170, A: 255})
				continue
			}
			gray := uint8((uint16(currentPixel.R)*54 + uint16(currentPixel.G)*183 + uint16(currentPixel.B)*19) / 256)
			gray = uint8((uint16(gray) + 3*255) / 4)
			diff.SetNRGBA(x, y, color.NRGBA{R: gray, G: gray, B: gray, A: 255})
		}
	}
	if result.status == "unchanged" && result.changed != 0 {
		result.status = "changed"
	}
	if err := os.MkdirAll(filepath.Dir(diffPath), 0o755); err != nil {
		return comparison{}, err
	}
	file, err := os.Create(diffPath)
	if err != nil {
		return comparison{}, err
	}
	encodeErr := png.Encode(file, diff)
	closeErr := file.Close()
	if encodeErr != nil {
		return comparison{}, encodeErr
	}
	if closeErr != nil {
		return comparison{}, closeErr
	}
	return result, nil
}

func decodePNG(path string) (image.Image, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	picture, err := png.Decode(file)
	if err != nil {
		return nil, err
	}
	return picture, nil
}

func imageBounds(path string) (image.Rectangle, error) {
	file, err := os.Open(path)
	if err != nil {
		return image.Rectangle{}, err
	}
	defer file.Close()
	config, err := png.DecodeConfig(file)
	if err != nil {
		return image.Rectangle{}, err
	}
	return image.Rect(0, 0, config.Width, config.Height), nil
}

func pixelAt(picture image.Image, x, y int) (color.NRGBA, bool) {
	bounds := picture.Bounds()
	if x >= bounds.Dx() || y >= bounds.Dy() {
		return color.NRGBA{}, false
	}
	return color.NRGBAModel.Convert(picture.At(bounds.Min.X+x, bounds.Min.Y+y)).(color.NRGBA), true
}

func slashRelative(root, path string) string {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(relative)
}

func writeGallery(path string, data manifest) error {
	encoded, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("encode gallery data: %w", err)
	}
	page, err := template.New("gallery").Parse(galleryHTML)
	if err != nil {
		return fmt.Errorf("parse gallery template: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create UI gallery: %w", err)
	}
	defer file.Close()
	if err := page.Execute(file, map[string]any{"Data": template.JS(encoded)}); err != nil {
		return fmt.Errorf("write UI gallery: %w", err)
	}
	return nil
}

const galleryHTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Loom UI Review</title>
<style>
:root{color-scheme:light;--ink:#17211b;--muted:#647269;--paper:#eef3ef;--card:#fff;--green:#239b68;--red:#b33a3a;--line:#dfe7e2}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI","Microsoft YaHei",sans-serif}header{position:sticky;top:0;z-index:3;padding:18px 24px;background:rgba(255,255,255,.96);border-bottom:1px solid var(--line);backdrop-filter:blur(10px)}h1{margin:0 0 10px;font-size:22px}.filters{display:flex;gap:8px;flex-wrap:wrap}.filters button,.copy{border:1px solid var(--line);border-radius:9px;background:white;padding:7px 11px;cursor:pointer}.filters button.active{background:var(--green);border-color:var(--green);color:white}main{display:grid;gap:18px;padding:22px}.scene{background:var(--card);border:1px solid var(--line);border-radius:14px;overflow:hidden}.scene-head{display:flex;align-items:center;gap:12px;padding:12px 15px;border-bottom:1px solid var(--line)}.scene-id{font:600 14px ui-monospace,SFMono-Regular,Consolas,monospace}.status{margin-left:auto;border-radius:99px;padding:4px 9px;font-size:12px}.unchanged{background:#eaf6f0;color:#147248}.changed,.size-changed,.missing-baseline,.missing-current{background:#fff0ef;color:var(--red)}.meta{padding:0 15px 12px;color:var(--muted);font-size:12px}.panes{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1px;background:var(--line)}.pane{min-width:0;background:#f8faf9;padding:10px}.pane h2{margin:0 0 8px;color:var(--muted);font-size:12px;text-transform:uppercase}.pane img{display:block;width:100%;height:auto;background:white;border:1px solid var(--line)}.missing{display:grid;min-height:180px;place-items:center;color:var(--red)}.overlay-wrap{position:relative;overflow:hidden}.overlay-wrap img{margin:0}.overlay-current{position:absolute;inset:0;clip-path:inset(0 50% 0 0)}.slider{width:100%;margin:8px 0 0}.empty{padding:80px;text-align:center;color:var(--muted)}@media(max-width:900px){.panes{grid-template-columns:1fr}.scene-head{align-items:flex-start;flex-wrap:wrap}.status{margin-left:0}}
</style>
</head>
<body>
<header><h1>Loom 原生 UI 审查</h1><div class="filters"><button data-filter="all" class="active">全部</button><button data-filter="android">Android</button><button data-filter="windows">Windows</button><button data-filter="changed">仅差异</button></div></header>
<main id="gallery"></main>
<script>
const review={{.Data}};let active="all";const gallery=document.querySelector("#gallery");
function imagePane(title,src,missing){const pane=document.createElement("section");pane.className="pane";const heading=document.createElement("h2");heading.textContent=title;pane.append(heading);if(!src){const absent=document.createElement("div");absent.className="missing";absent.textContent=missing;pane.append(absent);return pane}const img=document.createElement("img");img.src=src+"?g="+review.generation;img.loading="lazy";img.alt=title;pane.append(img);return pane}
function render(){gallery.replaceChildren();const scenes=review.scenes.filter(s=>active==="all"||s.platform===active||(active==="changed"&&s.status!=="unchanged"));if(!scenes.length){const empty=document.createElement("div");empty.className="empty";empty.textContent="没有符合筛选条件的场景";gallery.append(empty);return}for(const scene of scenes){const card=document.createElement("article");card.className="scene";const head=document.createElement("div");head.className="scene-head";const id=document.createElement("span");id.className="scene-id";id.textContent=scene.platform+"/"+scene.id;const copy=document.createElement("button");copy.className="copy";copy.textContent="复制场景 ID";copy.onclick=()=>navigator.clipboard.writeText(id.textContent);const status=document.createElement("span");status.className="status "+scene.status;const statusLabel=scene.status==="unchanged"?"无差异":scene.status;status.textContent=statusLabel+" · "+scene.changed_pixels+" px";head.append(id,copy,status);card.append(head);const meta=document.createElement("div");meta.className="meta";const values=Object.entries(scene.metadata||{}).map(([k,v])=>k+"="+v);meta.textContent=scene.width+"×"+scene.height+(values.length?" · "+values.join(" · "):"");card.append(meta);const panes=document.createElement("div");panes.className="panes";panes.append(imagePane("Baseline",scene.baseline,"缺少基准图"),imagePane("Current",scene.current,"缺少当前渲染"),imagePane("Diff",scene.diff,"无差异图"));card.append(panes);if(scene.baseline&&scene.current){const overlay=document.createElement("section");overlay.className="pane";const heading=document.createElement("h2");heading.textContent="叠加对比";const wrap=document.createElement("div");wrap.className="overlay-wrap";const base=document.createElement("img");base.src=scene.baseline+"?g="+review.generation;base.alt="baseline";const current=document.createElement("img");current.src=scene.current+"?g="+review.generation;current.className="overlay-current";current.alt="current";const slider=document.createElement("input");slider.type="range";slider.min=0;slider.max=100;slider.value=50;slider.className="slider";slider.oninput=()=>current.style.clipPath="inset(0 "+(100-slider.value)+"% 0 0)";wrap.append(base,current);overlay.append(heading,wrap,slider);card.append(overlay)}gallery.append(card)}}
document.querySelectorAll("[data-filter]").forEach(button=>button.onclick=()=>{active=button.dataset.filter;document.querySelectorAll("[data-filter]").forEach(item=>item.classList.toggle("active",item===button));render()});render();
setInterval(async()=>{try{const next=await fetch("manifest.json?poll="+Date.now(),{cache:"no-store"}).then(r=>r.json());if(next.generation!==review.generation)location.reload()}catch(_){}},1500);
</script>
</body>
</html>`
