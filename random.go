package mbpqs

import (
	"crypto/rand"
	"log"
)

// Create a n-byte slice of random bytes.
func randomBytes(n uint32) []byte {
	r := make([]byte, n)
	_, err := rand.Read(r)
	if err != nil {
		log.Fatal(err)
	}
	return r
}
