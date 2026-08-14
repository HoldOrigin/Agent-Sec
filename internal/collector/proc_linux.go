//go:build linux

package collector

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	containerIDPattern = regexp.MustCompile(`(?:^|[-/])([a-f0-9]{64})(?:\.scope)?(?:$|/)`)
	podUIDPattern      = regexp.MustCompile(`pod([0-9a-fA-F_-]{20,})`)
)

type ProcEnricher struct{}

func (ProcEnricher) Lookup(pid uint32) ContainerInfo {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "cgroup"))
	if err != nil {
		return ContainerInfo{}
	}
	text := string(data)
	info := ContainerInfo{}
	if match := containerIDPattern.FindStringSubmatch(text); len(match) == 2 {
		info.ContainerID = match[1]
	}
	if match := podUIDPattern.FindStringSubmatch(text); len(match) == 2 {
		info.PodUID = strings.ReplaceAll(match[1], "_", "-")
	}
	return info
}

func ReadHostInfo() (HostInfo, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return HostInfo{}, fmt.Errorf("read hostname: %w", err)
	}
	bootIDBytes, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return HostInfo{}, fmt.Errorf("read boot ID: %w", err)
	}
	bootTime, err := readBootTime()
	if err != nil {
		return HostInfo{}, err
	}
	hash := sha256.Sum256([]byte(hostname))
	return HostInfo{HostID: hostname + "-" + hex.EncodeToString(hash[:4]), BootID: strings.TrimSpace(string(bootIDBytes)), BootTime: bootTime}, nil
}

func readBootTime() (time.Time, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return time.Time{}, fmt.Errorf("open /proc/stat: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[0] == "btime" {
			seconds, parseErr := strconv.ParseInt(fields[1], 10, 64)
			if parseErr != nil {
				return time.Time{}, fmt.Errorf("parse kernel boot time: %w", parseErr)
			}
			return time.Unix(seconds, 0).UTC(), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return time.Time{}, fmt.Errorf("read /proc/stat: %w", err)
	}
	return time.Time{}, fmt.Errorf("kernel boot time is missing from /proc/stat")
}

func currentPID() int { return os.Getpid() }
