// Package deployhost executes deployment operations through the operator's
// existing .env -> YAML -> SSH configuration. It owns no device or job state.
package deployhost

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"loom/internal/control"
	"loom/internal/localconfig"
)

type Executor struct{ envPath string }

func New(envPath string) (*Executor, error) {
	if _, err := localconfig.Load(envPath); err != nil {
		return nil, errors.New("SSH deployment inputs cannot be loaded")
	}
	return &Executor{envPath: envPath}, nil
}

func (executor *Executor) Targets() ([]string, error) {
	config, err := localconfig.Load(executor.envPath)
	if err != nil {
		return nil, errors.New("SSH deployment inputs cannot be loaded")
	}
	return append([]string{}, config.DeployHosts...), nil
}

// Remote stderr is never returned to the Web: it may contain private file
// references or an untrusted login banner. These codes describe actual process
// results without interpreting a dropped SSH connection as an installation failure.
type Failure struct {
	Code     string
	ExitCode int
}

func (failure *Failure) Error() string             { return failure.Code }
func (failure *Failure) SSHFailure() (string, int) { return failure.Code, failure.ExitCode }

func commandEnvironment() []string {
	env := []string{}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "GANDI_PAT_TOKEN=") {
			env = append(env, entry)
		}
	}
	return env
}

type boundedOutput struct {
	bytes.Buffer
	exceeded bool
}

func (out *boundedOutput) Write(body []byte) (int, error) {
	if len(body) > (64<<10)-out.Len() {
		out.exceeded = true
		return 0, errors.New("SSH output exceeds the readback boundary")
	}
	return out.Buffer.Write(body)
}

func run(ctx context.Context, input, name string, args ...string) ([]byte, error) {
	return runInput(ctx, strings.NewReader(input), name, args...)
}

func runInput(ctx context.Context, input io.Reader, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env, command.Stdin = commandEnvironment(), input
	command.WaitDelay = 3 * time.Second
	output := &boundedOutput{}
	stderr := &boundedOutput{}
	command.Stdout = output
	command.Stderr = stderr
	err := command.Run()
	if ctx.Err() != nil {
		return nil, &Failure{Code: "connection_interrupted"}
	}
	if output.exceeded {
		return nil, &Failure{Code: "readback_exceeds_limit"}
	}
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			if exit.ExitCode() == 255 {
				return nil, &Failure{Code: "connection_unconfirmed", ExitCode: 255}
			}
			// Only known fixed installer diagnostics are projected. Never forward
			// arbitrary stderr, shell arguments, private paths, or invitations.
			for _, reason := range []struct{ text, code string }{
				{"This installer requires Linux.", "target_requires_linux"},
				{"The target architecture is unsupported.", "target_architecture_unsupported"},
				{"This release has no verified package for the target architecture.", "target_package_unavailable"},
				{"Required installation tool is missing.", "target_tool_missing"},
				{"a password is required", "target_privilege_required"},
				{"No distribution root supplied the verified installer.", "target_installer_unavailable"},
				{"No distribution root supplied the verified package.", "target_package_unavailable"},
				{"another Linux installation is running", "target_installation_running"},
				{"enrollment has not completed; activation withheld", "target_enrollment_incomplete"},
				{"exact service process and current authenticated runtime were not read back", "target_runtime_unconfirmed"},
			} {
				if strings.Contains(stderr.String(), reason.text) {
					return nil, &Failure{Code: reason.code, ExitCode: exit.ExitCode()}
				}
			}
			return nil, &Failure{Code: "target_command_failed", ExitCode: exit.ExitCode()}
		}
		return nil, &Failure{Code: "executor_unavailable"}
	}
	return output.Bytes(), nil
}

func (executor *Executor) resolve(ctx context.Context, alias string) (control.SSHTargetReadback, []string, error) {
	result := control.SSHTargetReadback{Alias: alias}
	if control.ValidateSSHTarget(alias) != nil {
		return result, nil, errors.New("invalid SSH target alias")
	}
	config, err := localconfig.Load(executor.envPath)
	if err != nil {
		return result, nil, errors.New("SSH deployment inputs cannot be loaded")
	}
	var node *localconfig.NodeNetwork
	for i := range config.Nodes {
		if config.Nodes[i].ID == alias {
			node = &config.Nodes[i]
			break
		}
	}
	if node == nil {
		return result, nil, errors.New("SSH target is absent from the selected deployment inputs")
	}
	result.ConfiguredHost, result.ConfiguredPort = node.ManagementHost, node.ManagementPort
	result.Local = alias == config.LocalNode
	if result.Local {
		result.ResolvedHost, result.ResolvedPort = node.ManagementHost, node.ManagementPort
		return result, nil, nil
	}
	// No forwarding or multiplexed session can outlive this command. Authentication
	// consumes existing operator inputs; a missing host key fails closed.
	args := []string{"-F", config.SSHConfig, "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ClearAllForwardings=yes", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2"}
	resolve, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	body, err := run(resolve, "", "ssh", append(append([]string{}, args...), "-G", alias)...)
	if err != nil {
		return result, nil, err
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch fields[0] {
		case "hostname":
			result.ResolvedHost = fields[1]
		case "port":
			result.ResolvedPort, _ = strconv.Atoi(fields[1])
		}
	}
	if result.ResolvedHost == "" || result.ResolvedPort < 1 || result.ResolvedPort > 65535 {
		return result, nil, errors.New("SSH target resolution is incomplete")
	}
	result.CoordinatesDiffer = result.ConfiguredHost != result.ResolvedHost || result.ConfiguredPort != result.ResolvedPort
	return result, append(args, alias), nil
}

func (executor *Executor) Resolve(ctx context.Context, alias string) (control.SSHTargetReadback, error) {
	value, _, err := executor.resolve(ctx, alias)
	return value, err
}

func (executor *Executor) Run(ctx context.Context, alias, verifiedScript string) ([]byte, error) {
	target, args, err := executor.resolve(ctx, alias)
	if err != nil {
		return nil, err
	}
	const shell = `if [ "$(id -u)" -eq 0 ]; then exec sh -s; else exec sudo -n sh -s; fi`
	if target.Local {
		return run(ctx, verifiedScript, "sh", "-c", shell)
	}
	return run(ctx, verifiedScript, "ssh", append(args, shell)...)
}

// Stream keeps public artifact bytes on stdin. The script is generated by the
// local caller; no private deployment input is interpreted as shell source.
func (executor *Executor) Stream(ctx context.Context, alias, script string, input io.Reader) ([]byte, error) {
	target, args, err := executor.resolve(ctx, alias)
	if err != nil {
		return nil, err
	}
	literal := "'" + strings.ReplaceAll(script, "'", "'\"'\"'") + "'"
	command := `if [ "$(id -u)" -eq 0 ]; then exec sh -c ` + literal + `; else exec sudo -n sh -c ` + literal + `; fi`
	if target.Local {
		return runInput(ctx, input, "sh", "-c", command)
	}
	return runInput(ctx, input, "ssh", append(args, command)...)
}
