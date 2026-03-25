package traefik_protector_mirror

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
)

// canonicalHeaders defines the ordered set of headers used for fingerprinting.
var canonicalHeaders = []string{
	"User-Agent",
	"Accept-Language",
	"Sec-Ch-Ua",
	"Sec-Ch-Ua-Mobile",
	"Sec-Ch-Ua-Platform",
}


// computeFingerprint computes the fingerprint ID from client IP and request headers.
// Algorithm: extract 4 canonical headers, normalize (trim+lowercase), join with "|",
// SHA-256, first 12 hex chars. Returns "{clientIP}:{hashPrefix}".
func computeFingerprint(clientIP string, headers http.Header) string {
	vals := make([]string, len(canonicalHeaders))
	for i, name := range canonicalHeaders {
		v := headers.Get(name)
		vals[i] = strings.ToLower(strings.TrimSpace(v))
	}
	concat := strings.Join(vals, "|")
	hash := sha256.Sum256([]byte(concat))
	prefix := fmt.Sprintf("%x", hash[:6])
	return clientIP + ":" + prefix
}
