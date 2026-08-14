//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "sentinel collector requires Linux with eBPF and BTF support")
	os.Exit(1)
}
