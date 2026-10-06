package releasedeploy

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"loom/internal/clientrelease"
)

// These scripts move verified public content through the existing SSH adapter.
// The receiver still validates one complete archive before changing its store.
func releaseRootScript(root string) string {
	return "release_root=$(cd -P " + literal(root) + " && pwd -P)\n"
}

func checkReuseFile(file clientrelease.TransferFile) string {
	return "release_file=\"$release_root\"/" + literal(file.Name) + "\n" +
		"[ -f \"$release_file\" ] && [ ! -L \"$release_file\" ] || exit 74\n" +
		"[ \"$(readlink -f -- \"$release_file\")\" = \"$release_root\"/" + literal(file.Name) + " ] || exit 74\n" +
		"[ \"$(stat -c %s -- \"$release_file\")\" = " + literal(strconv.FormatInt(file.Size, 10)) + " ] || exit 74\n" +
		"release_hash=$(sha256sum < \"$release_file\")\n" +
		"[ \"${release_hash%% *}\" = " + literal(strings.TrimPrefix(file.Digest, "sha256:")) + " ] || exit 74\n"
}

func reuseQueryScript(root string, files []clientrelease.TransferFile) string {
	var script strings.Builder
	script.WriteString("set -eu\n# Inspect existing release files; absence is not a cached success.\n")
	script.WriteString("if [ ! -e " + literal(root) + " ] && [ ! -L " + literal(root) + " ]; then exit 0; fi\n")
	script.WriteString(releaseRootScript(root))
	for index, file := range files {
		path := "\"$release_root\"/" + literal(file.Name)
		script.WriteString("if [ -e " + path + " ] || [ -L " + path + " ]; then\n")
		script.WriteString(checkReuseFile(file))
		fmt.Fprintf(&script, "printf '%%s\\n' %s\nfi\n", literal(strconv.Itoa(index)))
	}
	return script.String()
}

func reuseReadback(body []byte, files []clientrelease.TransferFile) ([]clientrelease.TransferFile, error) {
	result := []clientrelease.TransferFile{}
	previous := -1
	if len(body) == 0 {
		return result, nil
	}
	if body[len(body)-1] != '\n' {
		return nil, errors.New("incomplete file reuse readback")
	}
	for _, line := range strings.Split(string(body[:len(body)-1]), "\n") {
		index, err := strconv.Atoi(line)
		if err != nil || strconv.Itoa(index) != line || index <= previous || index >= len(files) {
			return nil, errors.New("unknown or ambiguous file reuse readback")
		}
		result = append(result, files[index])
		previous = index
	}
	return result, nil
}

// Concatenation does not extract the network input. The ordinary strict archive
// receiver rejects any extra/unsafe member, changed bytes or missing signature.
// GNU tar's single-block records preserve the receiver's exact EOF boundary.
func assembleArchiveScript(root string, reuse []clientrelease.TransferFile) string {
	var script strings.Builder
	if len(reuse) != 0 {
		script.WriteString(releaseRootScript(root))
		script.WriteString(": > \"$release_tmp/reused.list\"\n")
		for _, file := range reuse {
			script.WriteString(checkReuseFile(file))
			fmt.Fprintf(&script, "printf '%%s\\0' %s >> \"$release_tmp/reused.list\"\n", literal(file.Name))
		}
	}
	script.WriteString("cat > \"$release_tmp/incoming.tar\"\n")
	if len(reuse) != 0 {
		var additional int64
		for _, file := range reuse {
			additional += 512 + (file.Size+511)/512*512
		}
		// GNU concatenation includes the second archive's end records as well
		// as its own. Preserve the received length, adding only reused members;
		// any trailing bytes in the network input therefore remain detectable.
		fmt.Fprintf(&script, "release_size=$(stat -c %%s -- \"$release_tmp/incoming.tar\")\nrelease_size=$((release_size + %d))\n", additional)
		script.WriteString("tar --create --file \"$release_tmp/reused.tar\" --format=ustar --blocking-factor=1 --mode=0644 --owner=0 --group=0 --mtime=@0 --hard-dereference --no-recursion --directory \"$release_root\" --null --verbatim-files-from --files-from \"$release_tmp/reused.list\"\n")
		script.WriteString("tar --concatenate --blocking-factor=1 --file \"$release_tmp/incoming.tar\" \"$release_tmp/reused.tar\"\n")
		script.WriteString("[ \"$(stat -c %s -- \"$release_tmp/incoming.tar\")\" -ge \"$release_size\" ] || exit 74\ntruncate --size \"$release_size\" -- \"$release_tmp/incoming.tar\"\n")
	}
	return script.String()
}
