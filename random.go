package mbpqs

import (
	"crypto/rand"
)

// Create a n-byte slice of random bytes.
func randomBytes(n uint32) ([]byte, error) {
	r := make([]byte, n)
	_, err := rand.Read(r)
	if err != nil {
		return nil, err
	}
	return r, nil
}
