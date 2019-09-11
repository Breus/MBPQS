package mbpqs

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"reflect"

	"github.com/templexxx/xor"
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
	hVal reflect.Value
}

// This function initializes the precomputedHashes with their precomputed values.
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

	// Add paddingPRF and skSeed to the running hash.
	if skSeed != nil {
		hashPrfSk.Write(encodeUint64(hashPaddingPRF, int(ctx.params.n)))
		hashPrfSk.Write(skSeed)
	}

	hashPrfPub.Write(encodeUint64(hashPaddingPRF, int(ctx.params.n)))
	hashPrfPub.Write(pubSeed)

	/* See https://stackoverflow.com/questions/45385707/ for why this trick is prefered.
	 * This might break if sha{256,512}.digest is changed later.
	 */
	hashValPrfPub := reflect.ValueOf(hashPrfPub).Elem()
	hashValPrfSk := reflect.ValueOf(hashPrfSk).Elem()

	ph.prfAddrPubSeedInto = func(pad scratchPad, addr address, out []byte) {
		// Write the precomputed hash value on the hashPad.
		pad.hashPad.hVal.Set(hashValPrfPub)

		// Write the latest hash function state (with addr) on the hashPad.
		addrBuf := pad.prfAddrBuf()
		addr.writeInto(addrBuf)
		pad.hashPad.h.Write(addrBuf)

		// hash.Sum appends the hash to the input byte slice. As our input
		// byte slice hash enough capacity, it will write it in/out in there.
		pad.hashPad.h.Sum(out[:0])
	}
	if skSeed == nil {
		return
	}

	ph.prfAddrSkSeedInto = func(pad scratchPad, addr address, out []byte) {
		// This is exactly the same as for the pubSeed, but now for the skSeed.
		pad.hashPad.hVal.Set(hashValPrfSk)
		addrBuf := pad.prfAddrBuf()
		addr.writeInto(addrBuf)
		pad.hashPad.h.Write(addrBuf)
		pad.hashPad.h.Sum(out[:0]) // Again, in/out on the input.
	}
	return
}

// Compute the hash of in(put) into out, which must be a n-byte slice.
func (ctx *Context) hashInto(pad scratchPad, in, out []byte) {
	if ctx.params.n == 32 {
		ret := sha256.Sum256(in)
		copy(out, ret[:])
	} else { // N == 64
		ret := sha512.Sum512(in)
		copy(out, ret[:])
	}
}

// Creating a newHashScratchPad for the appropriate hash function.
func (ctx *Context) newHashScratchPad() (pad hashScratchPad) {
	if ctx.params.n == 32 {
		pad.h = sha256.New()
	} else { // n == 64
		pad.h = sha512.New()
	}
	pad.hVal = reflect.ValueOf(pad.h).Elem()
	return
}

/* From here on, the functions F, H, H_Msg, and PRF are implemented.
 * F(toByte(0,32) || KEY || i):
 * H(toByte(1,32) || KEY || i): hash up nodes in trees.
 * H_msg(toByte(2,32) || KEY || i): compute digest of message to sign.
 * PRF(toByte(3,32) || KEY || i):
 */

// Compute F(toByte(0,32) || KEY || i)

/* Computes H(toByte(1,32) || KEY || i).
 * Used to hash up trees (lTree, RootTree, ChainTree).
 */
func (ctx *Context) hInto(pad scratchPad, left, right []byte,
	ph precomputedHashes, addr address, out []byte) {
	// Working in the hBuf from the scratchpad to avoid allocations.
	buf := pad.hBuf()
	// First n-byte padding including the type number.
	encodeUint64Into(hashPaddingH, buf[:ctx.params.n])
	// Generate n-byte key, so keyAndMask = 0
	addr.setKeyAndMask(0)
	// Place the generated key on the scratchpad.
	ph.prfAddrPubSeedInto(pad, addr, buf[ctx.params.n:ctx.params.n*2])
	// Now we generated the 2n-byte masking value and put it on the scratchpad.
	// First the most significant n-bytes:
	addr.setKeyAndMask(1)
	ph.prfAddrPubSeedInto(pad, addr, buf[ctx.params.n*2:ctx.params.n*3])
	// Least-significant n-bytes of the 2n-byte mask:
	addr.setKeyAndMask(2)
	ph.prfAddrPubSeedInto(pad, addr, buf[ctx.params.n*3:])

	// Xorring 2n-byte mask r with the input.
	xor.BytesSameLen(buf[ctx.params.n*2:ctx.params.n*3], left, buf[ctx.params.n*2:ctx.params.n*3])
	xor.BytesSameLen(buf[ctx.params.n*3:], right, buf[ctx.params.n*3:])

	ctx.hashInto(pad, buf, out)
}

// Compute PRF(toByte(3,32) || KEY || i)
func (ctx *Context) prfUint64(pad scratchPad, i uint64, key []byte) []byte {
	ret := make([]byte, ctx.params.n)
	ctx.prfUint64Into(pad, i, key, ret)
	return ret
}

// Compute PRF(toByte(3,32 || KEY ||i) into out
func (ctx *Context) prfUint64Into(pad scratchPad, i uint64, key, out []byte) {
	buf := pad.prfBuf()
	// Put the n-byte padding into the buffer.
	encodeUint64Into(hashPaddingPRF, buf[:ctx.params.n])
	// Append the n-byte key to it.
	copy(buf[ctx.params.n:], key)
	// Append the input i to it.
	encodeUint64Into(i, buf[ctx.params.n*2:])
	// Hash it into out.
	ctx.hashInto(pad, buf, out)
}
