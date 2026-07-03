package enrich

// GuessOSFromTTL returns a best-guess operating system based on the
// initial TTL value found in the IP header.
func GuessOSFromTTL(ttl int) string {
	switch {
	case ttl == 0:
		return ""
	case ttl <= 64:
		return "Linux / Unix / Android"
	case ttl <= 128:
		return "Windows"
	case ttl <= 255:
		return "BSD / iOS / Mac / Cisco"
	default:
		return "Unknown"
	}
}