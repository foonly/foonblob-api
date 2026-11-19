package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/foonly/foonblob-api/internal/store"
)

// maxClockSkew is how far a request timestamp may deviate from server time.
const maxClockSkew = 300 // seconds

var (
	errTimestampWindow = errors.New("timestamp expired or invalid")
	errMissingSig      = errors.New("missing signature")
	errSigEncoding     = errors.New("invalid signature encoding")
	errBadSig          = errors.New("invalid signature")
)

// authenticate checks a request timestamp and HMAC-SHA256 signature. The signed
// message is the decimal timestamp followed by content.
//
// On success it returns the signature for replay protection: the caller must
// consume it in the store, which rejects any signature it has seen before. It is
// canonical (lowercase hex) so a replay cannot slip through by changing the case,
// and is remembered until the timestamp can no longer pass the window check.
func authenticate(secret string, ts int64, content, sigHex string) (store.Signature, error) {
	now := time.Now().Unix()
	if ts < now-maxClockSkew || ts > now+maxClockSkew {
		return store.Signature{}, errTimestampWindow
	}
	if sigHex == "" {
		return store.Signature{}, errMissingSig
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return store.Signature{}, errSigEncoding
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(ts, 10)))
	mac.Write([]byte(content))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return store.Signature{}, errBadSig
	}
	return store.Signature{Value: hex.EncodeToString(sig), ExpiresAt: ts + maxClockSkew + 60}, nil
}

// sha256Hex returns the hex-encoded SHA-256 digest of b.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// normalizeOrigin validates and canonicalizes an origin value to the form browsers
// send in the Origin header: lowercase "scheme://host[:port]" with default ports
// removed. Paths, queries and fragments are stripped; wildcards are rejected.
func normalizeOrigin(raw string) (string, error) {
	if raw == "*" {
		return "", errors.New("wildcard is not a valid allowed origin")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("invalid origin: " + err.Error())
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errors.New("origin must use http or https scheme, got " + strconv.Quote(u.Scheme))
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", errors.New("origin must include a host")
	}
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if strings.Contains(host, ":") { // IPv6 literal
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host, nil
}

// originAllowed reports whether a request Origin header is permitted for an
// identity. An empty allowed origin means no restriction. Requests without an
// Origin header (native/CLI clients) are allowed; they are authenticated by HMAC.
func originAllowed(reqOrigin, allowed string) bool {
	if allowed == "" || reqOrigin == "" {
		return true
	}
	if reqOrigin == allowed {
		return true
	}
	a, err1 := normalizeOrigin(reqOrigin)
	b, err2 := normalizeOrigin(allowed)
	return err1 == nil && err2 == nil && a == b
}
