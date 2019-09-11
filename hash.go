package mbpqs

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"reflect"
)

const (
	// Const in: F(toByte(0,32) || KEY || M)
	hashPaddingF = 0
	// Const in H(toByte(1,32) || KEY || M)
	hashPaddingH = 1
	// Const in: H_msg(toByte(2,32) || KEY || M)
	hashPaddingHashMsg = 2
	// Const in: PRF(toByte(3,32) || KEY || M)
	hashPaddingPRF = 3
)

/* Many of the hashes computed by MBPQS share the same prefix (pubSeed or skSeed).
 * Instead of computing the digest of this prefix over and over again, we can precompute the state of the hash after consuming these prefixes.
 * This struct contains the functions that encapsulate the precomputed hashes.
 */
type precomputedHashes struct {
	// Precomputed prf for the current pubSeed.
	prfAddrPubSeedInto func(pad scratchPad, addr address, out []byte)

	// Precomputed prfAddrInto for the current skSeed.
	prfAddrSkSeedInto func(pad scratchPad, addr address, out []byte)
}

// Scratchpad for hashing operations. Has pre-allocated memory to avoid many memory allocations.
type hashScratchPad struct {
	// Defines the hash function.
	h hash.Hash
	// Hash value, holds the hash (digest) value.
	hV reflect.Value
}

func (ctx *Context) precomputedHashes(pubSeed, skSeed []byte) (
	ph precomputedHashes) {
	var hashPrfSk, hashPrfPub hash.Hash
	if ctx.params.n == 32 {
		hashPrfSk = sha256.New()
		hashPrfPub = sha256.New()
	} else { // n = 64
		hashPrfSk = sha512.New()
		hashPrfPub = sha512.New()
	}
}
