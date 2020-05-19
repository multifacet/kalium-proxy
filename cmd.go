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

package main

import (
	"context"
	//"net/http"
	"flag"
	//"log"
	"fmt"
	"strconv"
	"sync"

	"github.com/google/subcommands"
	//"gvisor.dev/gvisor/pkg/log"
	//"gvisor.dev/gvisor/runsc/flag"
	//"gvisor.dev/gvisor/runsc/seclambda"
)

type Seclambda struct {
	ctrAddr  string
	ctrPort  int
	ioFDs    intFlags
	hostName string
}

// Name implements subcommands.Command.
func (*Seclambda) Name() string {
	return "seclambda"
}

// Synopsis implements subcommands.Command.
func (*Seclambda) Synopsis() string {
	return "launch the seclambda proxy process that communicates with the controller server"
}

// Usage implements subcommands.Command.
func (*Seclambda) Usage() string {
	return `seclambda [flags]`
}

type intFlags []int

// String implements flag.Value.
func (i *intFlags) String() string {
	return fmt.Sprintf("%v", *i)
}

// Get implements flag.Value.
func (i *intFlags) Get() interface{} {
	return i
}

// GetArray returns array of FDs.
func (i *intFlags) GetArray() []int {
	return *i
}

// Set implements flag.Value.
func (i *intFlags) Set(s string) error {
	fd, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("invalid flag value: %v", err)
	}
	if fd < 0 {
		return fmt.Errorf("flag value must be greater than 0: %d", fd)
	}
	*i = append(*i, fd)
	return nil
}

// SetFlags implements subcommands.Command.
func (g *Seclambda) SetFlags(f *flag.FlagSet) {
	f.StringVar(&g.ctrAddr, "address", "", "Address of the seclambda controller")
	f.IntVar(&g.ctrPort, "port", 5000, "Seclambda controller port")
	f.Var(&g.ioFDs, "io-fds", "First FD delivers messages from the sandbox, the second for talking to the sandbox from Seclambda")
	f.StringVar(&g.hostName, "hostname", "test0", "the container name which is sent to the guard")
}

// Execute implements subcommands.Command.
func (g *Seclambda) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	var wg sync.WaitGroup
	/*
		resp, err := http.Get("http://pages.cs.wisc.edu/")
		if err != nil {
			// handle error
			log.Debugf("[Seclambda] #1 Connect to wisc.edu failed: %v", err)
		} else {
			log.Debugf("[Seclambda] #1 Connect succeeded!")
			log.Debugf("[Seclambda] #1 Response: %v", resp)
		}*/

	guard := New(g.ctrAddr, g.ctrPort, g.ioFDs[0], g.ioFDs[1], g.hostName)

	wg.Add(1)
	go guard.Run(&wg)
	wg.Wait()
	//log.Infof("[Seclambda] Ran the seclambda subcommand!")
	return subcommands.ExitSuccess
}
