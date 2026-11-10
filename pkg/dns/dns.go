package dns

import (
	"context"
	"net"
	"strings"
	"time"
	"unicode"
)

const TXTSubdomainPrefix = "_sshcast."

// IsDNSDiscoveryEntry returns (domain, true) if entry represents a domain to be resolved
// via _sshcast.<domain> TXT records (e.g. "sshcast.net", "dns:sshcast.net", "_sshcast.sshcast.net"),
// or ("", false) if entry is already an explicit http:// or https:// coordinator URL.
func IsDNSDiscoveryEntry(entry string) (string, bool) {
	trimmed := strings.TrimRight(strings.TrimSpace(entry), "/.")
	if trimmed == "" {
		return "", false
	}
	lower := strings.ToLower(trimmed)
	for _, prefix := range []string{"dns:", "txt:"} {
		if strings.HasPrefix(lower, prefix) {
			rest := strings.TrimSpace(lower[len(prefix):])
			rest = strings.TrimPrefix(rest, "https://")
			rest = strings.TrimPrefix(rest, "http://")
			rest = strings.TrimRight(rest, "/.")
			if rest != "" {
				return rest, true
			}
			return "", false
		}
	}
	for _, scheme := range []string{"https://", "http://", "wss://", "ws://"} {
		if strings.HasPrefix(lower, scheme) {
			rest := lower[len(scheme):]
			host := strings.TrimRight(strings.SplitN(rest, "/", 2)[0], ".")
			if strings.HasPrefix(host, TXTSubdomainPrefix) {
				return host, true
			}
			return "", false
		}
	}
	return lower, true
}

// TXTLookupQName normalizes a domain or _sshcast.<domain> into the exact DNS QNAME for TXT lookup.
func TXTLookupQName(domain string) string {
	cleaned := strings.ToLower(strings.TrimSpace(domain))
	for _, prefix := range []string{"dns:", "txt:", "https://", "http://"} {
		cleaned = strings.TrimPrefix(cleaned, prefix)
	}
	cleaned = strings.TrimRight(cleaned, "/.")
	if cleaned == "" {
		return ""
	}
	if strings.HasPrefix(cleaned, TXTSubdomainPrefix) {
		return cleaned
	}
	return TXTSubdomainPrefix + cleaned
}

// NormalizeCoordinatorURL normalizes a coordinator hostname or URL token into an https:// (or http://) URL.
func NormalizeCoordinatorURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	trimmed = strings.Trim(trimmed, "\"'")
	trimmed = strings.TrimSpace(trimmed)
	trimmed = strings.TrimRight(trimmed, "/.")
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "https://") || strings.HasPrefix(trimmed, "http://") {
		return trimmed
	}
	return "https://" + trimmed
}

func appendUnique(out []string, url string) []string {
	for _, existing := range out {
		if existing == url {
			return out
		}
	}
	return append(out, url)
}

// ParseTXTCoordinatorRecords parses DNS TXT record strings from _sshcast.<domain> into a deduplicated
// list of coordinator URLs (https://...).
func ParseTXTCoordinatorRecords(txtRecords []string) []string {
	var out []string
	for _, rawRecord := range txtRecords {
		record := strings.TrimSpace(strings.Trim(strings.TrimSpace(rawRecord), "\""))
		if record == "" {
			continue
		}
		if strings.Contains(record, "=") {
			for _, clause := range strings.Split(record, ";") {
				clause = strings.TrimSpace(clause)
				if clause == "" {
					continue
				}
				k, v, ok := strings.Cut(clause, "=")
				if !ok {
					continue
				}
				switch strings.ToLower(strings.TrimSpace(k)) {
				case "servers", "server", "coordinators", "coordinator", "hosts", "host", "urls", "url":
					items := strings.FieldsFunc(v, func(r rune) bool {
						return r == ',' || unicode.IsSpace(r)
					})
					for _, item := range items {
						if norm := NormalizeCoordinatorURL(item); norm != "" {
							out = appendUnique(out, norm)
						}
					}
				}
			}
		} else {
			tokens := strings.FieldsFunc(record, func(r rune) bool {
				return r == ',' || r == ';' || unicode.IsSpace(r)
			})
			for _, token := range tokens {
				if norm := NormalizeCoordinatorURL(token); norm != "" {
					out = appendUnique(out, norm)
				}
			}
		}
	}
	return out
}

// LookupCoordinatorsTXT queries DNS TXT records for _sshcast.<domain> and returns normalized coordinator URLs.
func LookupCoordinatorsTXT(ctx context.Context, domain string) ([]string, error) {
	qname := TXTLookupQName(domain)
	if qname == "" {
		return nil, nil
	}
	txts, err := net.DefaultResolver.LookupTXT(ctx, qname)
	if err != nil {
		return nil, err
	}
	return ParseTXTCoordinatorRecords(txts), nil
}

// ResolveCoordinatorServers resolves a slice of server entries (mixing direct URLs and DNS discovery domains).
func ResolveCoordinatorServers(ctx context.Context, entries []string) []string {
	var out []string
	for _, entry := range entries {
		if domain, ok := IsDNSDiscoveryEntry(entry); ok {
			lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			urls, err := LookupCoordinatorsTXT(lookupCtx, domain)
			cancel()
			if err == nil && len(urls) > 0 {
				for _, u := range urls {
					out = appendUnique(out, u)
				}
				continue
			}
			fallbackHost := strings.TrimPrefix(domain, TXTSubdomainPrefix)
			if norm := NormalizeCoordinatorURL(fallbackHost); norm != "" {
				out = appendUnique(out, norm)
			}
		} else if norm := NormalizeCoordinatorURL(entry); norm != "" {
			out = appendUnique(out, norm)
		}
	}
	return out
}
