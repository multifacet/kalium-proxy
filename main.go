// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Binary runsc is an implementation of the Open Container Initiative Runtime
// that runs applications inside a sandbox.
package main

import (
	"context"
	"flag"
	//"fmt"
	//"io"
	//"io/ioutil"
	"os"
	//"os/signal"
	//"path/filepath"
	//"strings"
	"syscall"
	//"time"

	"github.com/google/subcommands"
	//"gvisor.dev/gvisor/pkg/log"
	//"gvisor.dev/gvisor/pkg/refs"
	//"gvisor.dev/gvisor/pkg/sentry/platform"
	//"gvisor.dev/gvisor/runsc/boot"
	//"gvisor.dev/gvisor/runsc/cmd"
	//"gvisor.dev/gvisor/runsc/flag"
	//"gvisor.dev/gvisor/runsc/specutils"
)

var (
	// Although these flags are not part of the OCI spec, they are used by
	// Docker, and thus should not be changed.
	rootDir     = flag.String("root", "", "root directory for storage of container state.")
	logFilename = flag.String("log", "", "file path where internal debug information is written, default is stdout.")
	logFormat   = flag.String("log-format", "text", "log format: text (default), json, or json-k8s.")
	debug       = flag.Bool("debug", true, "enable debug logging.")
	showVersion = flag.Bool("version", false, "show version and exit.")
	// TODO(gvisor.dev/issue/193): support systemd cgroups
	systemdCgroup = flag.Bool("systemd-cgroup", false, "Use systemd for cgroups. NOT SUPPORTED.")

	// These flags are unique to runsc, and are used to configure parts of the
	// system that are not covered by the runtime spec.

	// Debugging flags.
	debugLog        = flag.String("debug-log", "", "additional location for logs. If it ends with '/', log files are created inside the directory with default names. The following variables are available: %TIMESTAMP%, %COMMAND%.")
	logPackets      = flag.Bool("log-packets", false, "enable network packet logging.")
	logFD           = flag.Int("log-fd", -1, "file descriptor to log to.  If set, the 'log' flag is ignored.")
	debugLogFD      = flag.Int("debug-log-fd", -1, "file descriptor to write debug logs to.  If set, the 'debug-log-dir' flag is ignored.")
	debugLogFormat  = flag.String("debug-log-format", "text", "log format: text (default), json, or json-k8s.")
	alsoLogToStderr = flag.Bool("alsologtostderr", false, "send log messages to stderr.")

	// Debugging flags: strace related
	strace         = flag.Bool("strace", true, "enable strace.")
	straceSyscalls = flag.String("strace-syscalls", "", "comma-separated list of syscalls to trace. If --strace is true and this list is empty, then all syscalls will be traced.")
	straceLogSize  = flag.Uint("strace-log-size", 1024, "default size (in bytes) to log data argument blobs.")

	// Flags that control sandbox runtime behavior.
	hardwareGSO        = flag.Bool("gso", true, "enable hardware segmentation offload if it is supported by a network device.")
	softwareGSO        = flag.Bool("software-gso", true, "enable software segmentation offload when hardware ofload can't be enabled.")
	platformName       = flag.String("platform", "ptrace", "specifies which platform to use: ptrace (default), kvm")
	network            = flag.String("network", "sandbox", "specifies which network to use: sandbox (default), host, none. Using network inside the sandbox is more secure because it's isolated from the host network.")
	fileAccess         = flag.String("file-access", "exclusive", "specifies which filesystem to use for the root mount: exclusive (default), shared. Volume mounts are always shared.")
	fsGoferHostUDS     = flag.Bool("fsgofer-host-uds", false, "allow the gofer to mount Unix Domain Sockets.")
	overlay            = flag.Bool("overlay", false, "wrap filesystem mounts with writable overlay. All modifications are stored in memory inside the sandbox.")
	overlayfsStaleRead = flag.Bool("overlayfs-stale-read", false, "reopen cached FDs after a file is opened for write to workaround overlayfs limitation on kernels before 4.19.")
	watchdogAction     = flag.String("watchdog-action", "log", "sets what action the watchdog takes when triggered: log (default), panic.")
	panicSignal        = flag.Int("panic-signal", -1, "register signal handling that panics. Usually set to SIGUSR2(12) to troubleshoot hangs. -1 disables it.")
	profile            = flag.Bool("profile", false, "prepares the sandbox to use Golang profiler. Note that enabling profiler loosens the seccomp protection added to the sandbox (DO NOT USE IN PRODUCTION).")
	netRaw             = flag.Bool("net-raw", true, "enable raw sockets. When false, raw sockets are disabled by removing CAP_NET_RAW from containers (`runsc exec` will still be able to utilize raw sockets). Raw sockets allow malicious containers to craft packets and potentially attack the network.")
	numNetworkChannels = flag.Int("num-network-channels", 1, "number of underlying channels(FDs) to use for network link endpoints.")
	rootless           = flag.Bool("rootless", false, "it allows the sandbox to be started with a user that is not root. Sandbox and Gofer processes may run with same privileges as current user.")
	referenceLeakMode  = flag.String("ref-leak-mode", "disabled", "sets reference leak check mode: disabled (default), log-names, log-traces.")
	cpuNumFromQuota    = flag.Bool("cpu-num-from-quota", false, "set cpu number to cpu quota (least integer greater or equal to quota value, but not less than 2)")

	// Test flags, not to be used outside tests, ever.
	testOnlyAllowRunAsCurrentUserWithoutChroot = flag.Bool("TESTONLY-unsafe-nonroot", false, "TEST ONLY; do not ever use! This skips many security measures that isolate the host from the sandbox.")
	testOnlyTestNameEnv                        = flag.String("TESTONLY-test-name-env", "", "TEST ONLY; do not ever use! Used for automated tests to improve logging.")
)

func main() {
	// Help and flags commands are generated automatically.
	//help := cmd.NewHelp(subcommands.DefaultCommander)
	//help.Register(new(cmd.Syscalls))
	//subcommands.Register(help, "")
	subcommands.Register(subcommands.FlagsCommand(), "")

	// Register user-facing runsc commands.
	subcommands.Register(new(Seclambda), "")

	// All subcommands must be registered before flag parsing.
	flag.Parse()

	// Call the subcommand and pass in the configuration.
	var ws syscall.WaitStatus
	subcmdCode := subcommands.Execute(context.Background(), &ws)
	if subcmdCode == subcommands.ExitSuccess {
		//log.Infof("Exiting with status: %v", ws)
		if ws.Signaled() {
			// No good way to return it, emulate what the shell does. Maybe raise
			// signall to self?
			os.Exit(128 + int(ws.Signal()))
		}
		os.Exit(ws.ExitStatus())
	}
	// Return an error that is unlikely to be used by the application.
	//log.Warningf("Failure to execute command, err: %v", subcmdCode)
	os.Exit(128)
}
