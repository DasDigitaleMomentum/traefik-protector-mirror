package protector_mirror

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
)

// canonicalHeaders defines the ordered set of headers used for fingerprinting.
// Must match the Collector's implementation exactly.
var canonicalHeaders = []string{
	"User-Agent",
	"Accept",
	"Accept-Language",
	"Accept-Encoding",
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
