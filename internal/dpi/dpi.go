package dpi

import (
	"bytes"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Inspection holds all DPI-extracted data
type Inspection struct {
	// HTTP
	HTTPMethod   string            `json:"http_method,omitempty"`
	HTTPURL      string            `json:"http_url,omitempty"`
	HTTPHost     string            `json:"http_host,omitempty"`
	HTTPHeaders  map[string]string `json:"http_headers,omitempty"`
	HTTPBody     string            `json:"http_body,omitempty"`
	
	// DNS
	DNSQuery     string   `json:"dns_query,omitempty"`
	DNSType      string   `json:"dns_type,omitempty"`
	DNSResponses []string `json:"dns_responses,omitempty"`
	
	// TLS
	TLSSNI       string `json:"tls_sni,omitempty"`
	TLSVersion   string `json:"tls_version,omitempty"`
	
	// Payload preview
	PayloadHex   string `json:"payload_hex,omitempty"`
	PayloadASCII string `json:"payload_ascii,omitempty"`
	
	// Sensitive data detection
	SensitiveData []SensitiveMatch `json:"sensitive_data,omitempty"`
}

type SensitiveMatch struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Context string `json:"context,omitempty"`
}

// Inspect performs DPI on a packet
func Inspect(pkt gopacket.Packet) *Inspection {
	insp := &Inspection{
		HTTPHeaders: make(map[string]string),
	}
	
	// Extract payload
	if app := pkt.ApplicationLayer(); app != nil {
		payload := app.Payload()
		if len(payload) > 0 {
			// Limit payload preview to first 512 bytes
			previewLen := 512
			if len(payload) < previewLen {
				previewLen = len(payload)
			}
			insp.PayloadHex = hex.EncodeToString(payload[:previewLen])
			insp.PayloadASCII = sanitizeASCII(payload[:previewLen])
			
			// Try to parse as HTTP
			parseHTTP(payload, insp)
			
			// Detect sensitive data
			insp.SensitiveData = detectSensitiveData(payload)
		}
	}
	
	// DNS
	if dns := pkt.Layer(layers.LayerTypeDNS); dns != nil {
		parseDNS(dns.(*layers.DNS), insp)
	}
	
	// TLS (try to extract SNI from ClientHello)
	if tcp := pkt.Layer(layers.LayerTypeTCP); tcp != nil {
		if app := pkt.ApplicationLayer(); app != nil {
			parseTLS(app.Payload(), insp)
		}
	}
	
	return insp
}

func parseHTTP(payload []byte, insp *Inspection) {
	// Check if it looks like HTTP
	if !bytes.HasPrefix(payload, []byte("GET ")) &&
		!bytes.HasPrefix(payload, []byte("POST ")) &&
		!bytes.HasPrefix(payload, []byte("PUT ")) &&
		!bytes.HasPrefix(payload, []byte("DELETE ")) &&
		!bytes.HasPrefix(payload, []byte("HTTP/")) {
		return
	}
	
	lines := strings.Split(string(payload), "\r\n")
	if len(lines) == 0 {
		return
	}
	
	// Parse request line
	parts := strings.Fields(lines[0])
	if len(parts) >= 2 {
		if strings.HasPrefix(lines[0], "HTTP/") {
			// Response
			insp.HTTPMethod = "RESPONSE"
			insp.HTTPURL = parts[0]
		} else {
			// Request
			insp.HTTPMethod = parts[0]
			insp.HTTPURL = parts[1]
			if len(parts) >= 3 {
				insp.HTTPHeaders["HTTP-Version"] = parts[2]
			}
		}
	}
	
	// Parse headers
	bodyStart := -1
	for i := 1; i < len(lines); i++ {
		if lines[i] == "" {
			bodyStart = i + 1
			break
		}
		if idx := strings.Index(lines[i], ":"); idx > 0 {
			key := strings.TrimSpace(lines[i][:idx])
			val := strings.TrimSpace(lines[i][idx+1:])
			insp.HTTPHeaders[key] = val
			if key == "Host" {
				insp.HTTPHost = val
			}
		}
	}
	
	// Extract body preview
	if bodyStart > 0 && bodyStart < len(lines) {
		body := strings.Join(lines[bodyStart:], "\r\n")
		if len(body) > 200 {
			body = body[:200] + "..."
		}
		insp.HTTPBody = body
	}
	
	// Clean up URL
	if insp.HTTPURL != "" && !strings.HasPrefix(insp.HTTPURL, "HTTP/") {
		if u, err := url.Parse(insp.HTTPURL); err == nil {
			if u.Host != "" {
				insp.HTTPHost = u.Host
			}
		}
	}
}

func parseDNS(dns *layers.DNS, insp *Inspection) {
	if len(dns.Questions) > 0 {
		q := dns.Questions[0]
		insp.DNSQuery = string(q.Name)
		insp.DNSType = q.Type.String()
	}
	
	for _, ans := range dns.Answers {
		if ans.IP != nil {
			insp.DNSResponses = append(insp.DNSResponses, ans.IP.String())
		} else if len(ans.Name) > 0 {
			insp.DNSResponses = append(insp.DNSResponses, string(ans.Name))
		}
	}
}

func parseTLS(payload []byte, insp *Inspection) {
	// Look for ClientHello with SNI extension
	// TLS record: ContentType(1) + Version(2) + Length(2) + ...
	if len(payload) < 5 {
		return
	}
	
	// ContentType 0x16 = Handshake
	if payload[0] != 0x16 {
		return
	}
	
	// Try to find SNI in the payload (simplified)
	// SNI extension type is 0x0000
	sniPattern := []byte{0x00, 0x00} // SNI extension type
	if idx := bytes.Index(payload, sniPattern); idx > 0 && idx < len(payload)-10 {
		// Extract hostname (simplified - real impl would parse TLV properly)
		// This is a best-effort extraction
		for i := idx + 10; i < len(payload)-10; i++ {
			// Look for printable ASCII hostname
			if payload[i] >= 0x20 && payload[i] <= 0x7e {
				end := i
				for end < len(payload) && payload[end] >= 0x20 && payload[end] <= 0x7e {
					end++
				}
				hostname := string(payload[i:end])
				if strings.Contains(hostname, ".") && len(hostname) > 3 && len(hostname) < 253 {
					insp.TLSSNI = hostname
					break
				}
			}
		}
	}
	
	// TLS version
	if len(payload) >= 3 {
		major := payload[1]
		minor := payload[2]
		if major == 0x03 {
			switch minor {
			case 0x01:
				insp.TLSVersion = "TLS 1.0"
			case 0x02:
				insp.TLSVersion = "TLS 1.1"
			case 0x03:
				insp.TLSVersion = "TLS 1.2"
			case 0x04:
				insp.TLSVersion = "TLS 1.3"
			}
		}
	}
}

func detectSensitiveData(payload []byte) []SensitiveMatch {
	var matches []SensitiveMatch
	text := string(payload)
	
	// Email addresses
	emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	for _, match := range emailRegex.FindAllString(text, 5) {
		matches = append(matches, SensitiveMatch{
			Type:  "Email",
			Value: match,
		})
	}
	
	// Credit card numbers (basic Luhn check)
	ccRegex := regexp.MustCompile(`\b(?:\d[ -]*?){13,16}\b`)
	for _, match := range ccRegex.FindAllString(text, 3) {
		cleaned := strings.ReplaceAll(strings.ReplaceAll(match, " ", ""), "-", "")
		if isValidCC(cleaned) {
			matches = append(matches, SensitiveMatch{
				Type:  "Credit Card",
				Value: maskCC(cleaned),
			})
		}
	}
	
	// API keys / tokens (common patterns)
	apiKeyPatterns := []struct {
		pattern *regexp.Regexp
		name    string
	}{
		{regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]?([a-zA-Z0-9]{20,})['"]?`), "API Key"},
		{regexp.MustCompile(`(?i)(token|bearer)\s*[:=]\s*['"]?([a-zA-Z0-9._-]{20,})['"]?`), "Token"},
		{regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*['"]?([^'"\s]{6,})['"]?`), "Password"},
	}
	
	for _, p := range apiKeyPatterns {
		if submatch := p.pattern.FindStringSubmatch(text); len(submatch) > 2 {
			matches = append(matches, SensitiveMatch{
				Type:  p.name,
				Value: submatch[2][:min(10, len(submatch[2]))] + "...",
			})
		}
	}
	
	return matches
}

func isValidCC(number string) bool {
	if len(number) < 13 || len(number) > 19 {
		return false
	}
	
	var sum int
	alternate := false
	for i := len(number) - 1; i >= 0; i-- {
		if number[i] < '0' || number[i] > '9' {
			return false
		}
		n := int(number[i] - '0')
		if alternate {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alternate = !alternate
	}
	return sum%10 == 0
}

func maskCC(number string) string {
	if len(number) <= 4 {
		return number
	}
	return "****-****-****-" + number[len(number)-4:]
}

func sanitizeASCII(data []byte) string {
	var result []byte
	for _, b := range data {
		if b >= 0x20 && b <= 0x7e {
			result = append(result, b)
		} else {
			result = append(result, '.')
		}
	}
	return string(result)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}