package session

import (
	"strconv"
	"strings"
)

// capabilities is the negotiated view of one connection.
type capabilities struct {
	swbreak      bool
	hwbreak      bool
	memMap       bool
	qRcmd        bool
	maxPacketLen int
	clientCount  int // number of features the client advertised
}

// parseClientCaps parses the payload after "qSupported". Each item is either
// "name+" (supported), "name-" (explicitly unsupported) or "name=value".
// A missing optional feature means the server degrades; a required feature
// explicitly rejected ("-") returns a fatal reason when StrictCaps is on.
func parseClientCaps(payload string) (capabilities, string) {
	var caps capabilities
	caps.maxPacketLen = packetSize
	parts := strings.Split(payload, ":")
	if len(parts) < 2 {
		// Bare "qSupported": nothing advertised; degrade everything optional.
		return caps, ""
	}
	for _, item := range strings.Split(parts[1], ";") {
		if item == "" {
			continue
		}
		caps.clientCount++
		name, sign, value := splitFeature(item)
		switch name {
		case capSWBreak:
			caps.swbreak = sign != "-"
		case capHWBreak:
			caps.hwbreak = sign != "-"
		case capMemMap:
			caps.memMap = sign != "-"
		case capRcmd:
			caps.qRcmd = sign != "-"
		case capPacketSize:
			if sign == "=" {
				// value can be "limit" or "recv,send"; take the first number.
				head := strings.SplitN(value, ",", 2)[0]
				if n, err := strconv.ParseInt(head, 16, 64); err == nil && n > 0 {
					caps.maxPacketLen = int(n)
				}
			}
		}
	}
	return caps, ""
}

// splitFeature divides "name+", "name-" or "name=value" into its parts.
func splitFeature(item string) (name, sign, value string) {
	if i := strings.IndexByte(item, '='); i >= 0 {
		return item[:i], "=", item[i+1:]
	}
	if strings.HasSuffix(item, "+") {
		return item[:len(item)-1], "+", ""
	}
	if strings.HasSuffix(item, "-") {
		return item[:len(item)-1], "-", ""
	}
	return item, "", ""
}

// explicitlyRejected reports whether the qSupported payload contains "name-".
func explicitlyRejected(payload, name string) bool {
	parts := strings.Split(payload, ":")
	if len(parts) < 2 {
		return false
	}
	for _, item := range strings.Split(parts[1], ";") {
		if n, sign, _ := splitFeature(item); n == name && sign == "-" {
			return true
		}
	}
	return false
}
