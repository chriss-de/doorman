package doorman

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
)

func WithHashAlgorithm(name string, f HasherFunc) func(dm *Doorman) error {
	return func(dm *Doorman) error {
		if name == "" || f == nil {
			return fmt.Errorf("hash algorithm must not be empty")
		}
		hashers[name] = f
		return nil
	}
}

func stringHashPlain(s string) string {
	return s
}

func stringHashSha256(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}

func stringHashSha1(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}

func stringHashMd5(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}
