package main

import "C"
import (
	"bufio"
	"fmt"
	"os"
	"regexp"
)

var (
	dockerPattern = regexp.MustCompile(`\d+:.+:/docker/([0-9a-f]{64})`)
)

//export LookupContainerID
func LookupContainerID (pid uint32) *C.char {

	containerID := ""
	f,err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		result := C.CString(containerID)
		return result
	}

	defer f.Close()

	scanner := bufio.NewScanner(f)

	// assume a docker environment
	for scanner.Scan() {
		line := scanner.Text()
		parts := dockerPattern.FindStringSubmatch(line)
		if parts != nil {
			containerID = parts[1]
			break
		}
	}

	result := C.CString(containerID)

	return result
}

func main() {}
