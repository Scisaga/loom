package linuxclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"sync"
)

// Probe tracing is an explicit process-local diagnostic option. Native Debug
// enables the existing WG stages, so filter that stream before it reaches the
// log destination: ordinary Debug/Info destinations are not diagnostic evidence.
func withProbeDebugConfig(source string) (string, error) {
	if source == "" {
		return source, nil
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal([]byte(source), &document); err != nil {
		return "", err
	}
	if document == nil {
		return "", errors.New("native diagnostic config must be an object")
	}
	document["log"] = json.RawMessage(`{"level":"debug"}`)
	body, err := json.Marshal(document)
	return string(body), err
}

type probeOutput struct {
	mu sync.Mutex
	io.Writer
}

func serializedProbeOutput(target io.Writer) io.Writer {
	if _, ok := target.(*probeOutput); ok {
		return target
	}
	return &probeOutput{Writer: target}
}

func (output *probeOutput) Write(body []byte) (n int, err error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	// Diagnostics must not turn a successful transport into a logging failure.
	defer func() { _ = recover(); n, err = len(body), nil }()
	_, _ = output.Writer.Write(body)
	return len(body), nil
}

type probeNativeLog struct {
	mu       sync.Mutex
	target   io.Writer
	pending  []byte
	dropping bool
}

var probeLogColor = regexp.MustCompile("\x1b\\[[0-9;]*m")
var probeLogID = regexp.MustCompile(`echo_id=[0-9a-f]{64} phase=[a-z-]+ elapsed_ns=[0-9]+ outcome=[a-z-]+ error_type=[A-Za-z0-9_.*<>]+\n$`)
var probeWGStage = regexp.MustCompile(`WG stage=(?:peer-prepare|inner-dial|execution-confirm) event=(?:begin|end elapsed=[0-9.a-zµ]+ canceled=(?:true|false) error_type=[A-Za-z0-9_.*<>]+)\n$`)
var probeNativeID = regexp.MustCompile(`\] \[([0-9]+) [^]\n]+\] `)

func probeNativeOutput(options Options) io.Writer {
	if !options.TraceProbes {
		return options.Log
	}
	// Each child gets its own framing buffer; all children and Go callbacks
	// share the synchronized destination, so partial lines cannot interleave.
	return &probeNativeLog{target: options.Log}
}

func safeProbeNativeLine(line []byte) []byte {
	plain := probeLogColor.ReplaceAll(line, nil)
	if bytes.HasPrefix(plain, []byte("DEBUG[")) {
		match := probeLogID.Find(plain)
		if match == nil {
			match = probeWGStage.Find(plain)
		}
		if match != nil {
			// Retain only fixed diagnostic fields, never an arbitrary logger tag
			// or message prefix. The existing native ID joins WG stages to Echo.
			prefix := []byte("DEBUG ")
			if id := probeNativeID.FindSubmatch(plain); id != nil {
				prefix = append(prefix, []byte("native_id=")...)
				prefix = append(prefix, id[1]...)
				prefix = append(prefix, ' ')
			}
			return append(prefix, match...)
		}
	}
	text := string(plain)
	for _, level := range []string{"WARN", "ERROR", "FATAL", "PANIC"} {
		if strings.HasPrefix(text, level+"[") || strings.HasPrefix(text, level+" ") {
			return line // Preserve the pre-existing warn/error stream.
		}
	}
	return nil
}

func (output *probeNativeLog) Write(body []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	const maximumLine = 32 << 10
	for rest := body; len(rest) > 0; {
		end := bytes.IndexByte(rest, '\n')
		piece := rest
		if end >= 0 {
			piece = rest[:end+1]
		}
		if len(output.pending)+len(piece) > maximumLine {
			output.pending = output.pending[:0]
			output.dropping = true
		}
		if !output.dropping {
			output.pending = append(output.pending, piece...)
		}
		if end < 0 {
			break
		}
		if !output.dropping {
			if line := safeProbeNativeLine(output.pending); line != nil {
				_, _ = output.target.Write(line)
			}
		}
		output.pending = output.pending[:0]
		output.dropping = false
		rest = rest[end+1:]
	}
	return len(body), nil
}
