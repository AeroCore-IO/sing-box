package hysteria2

import (
	"crypto/sha256"
	"encoding/hex"
)

func userName(name string, password string) string {
	if name != "" {
		return name
	}
	if password == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:8])
}
