package common

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ParsePortsField parses preset names ('quick', 'standard', 'full') or
// comma-separated lists and ranges ('80,443,8000-8100').
// It returns a deduplicated, sorted slice of valid port numbers (1-65535).
func ParsePortsField(ports string) ([]int, error) {
	p := strings.ToLower(strings.TrimSpace(ports))
	if p == "" {
		return nil, errors.New("empty port specification")
	}

	switch p {
	case PortPresetQuick:
		out := make([]int, len(QuickPorts))
		copy(out, QuickPorts)
		sort.Ints(out)
		return out, nil
	case PortPresetStandard:
		out := make([]int, len(StandardPorts))
		copy(out, StandardPorts)
		sort.Ints(out)
		return out, nil
	case PortPresetFull:
		out := make([]int, PortMax)
		for i := 0; i < PortMax; i++ {
			out[i] = i + 1
		}
		return out, nil
	}

	portSet := make(map[int]struct{})
	chunks := strings.Split(p, ",")
	validChunks := 0
	for _, chunk := range chunks {
		chunk = strings.TrimSpace(chunk)
		if chunk == "" {
			continue
		}
		validChunks++

		if strings.Contains(chunk, "-") {
			parts := strings.Split(chunk, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid port range syntax: '%s'", chunk)
			}
			startStr := strings.TrimSpace(parts[0])
			endStr := strings.TrimSpace(parts[1])
			if startStr == "" || endStr == "" {
				return nil, fmt.Errorf("invalid port range syntax: '%s'", chunk)
			}

			start, err1 := strconv.Atoi(startStr)
			end, err2 := strconv.Atoi(endStr)
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("invalid port number in range: '%s'", chunk)
			}
			if start < PortMin || end > PortMax {
				return nil, fmt.Errorf("port range boundary out of bounds [1-65535]: '%s'", chunk)
			}
			if start > end {
				return nil, fmt.Errorf("inverted port range [%d > %d]: '%s'", start, end, chunk)
			}
			for pt := start; pt <= end; pt++ {
				portSet[pt] = struct{}{}
			}
		} else {
			pt, err := strconv.Atoi(chunk)
			if err != nil {
				return nil, fmt.Errorf("invalid port number: '%s'", chunk)
			}
			if pt < PortMin || pt > PortMax {
				return nil, fmt.Errorf("port number out of bounds [1-65535]: %d", pt)
			}
			portSet[pt] = struct{}{}
		}
	}

	if validChunks == 0 || len(portSet) == 0 {
		return nil, errors.New("no valid ports found in specification")
	}

	result := make([]int, 0, len(portSet))
	for pt := range portSet {
		result = append(result, pt)
	}
	sort.Ints(result)
	return result, nil
}
