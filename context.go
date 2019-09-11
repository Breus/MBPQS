package mbpqs

import (
	"fmt"
)

// MBPQS instance.
type Context struct {
	params       Params // MBPQS parameters
	wotsLogW     uint8  // logarithm of the Winternitz parameter
	wotsLen1     uint32 // WOTS+ chains for message
	wotsLen2     uint32 // WOTS+ chains for checksum
	wotsLen      uint32 // total number of WOTS+ chains
	wotsSigBytes uint32 // length of WOTS+ signature
	// The amount of threads to use in the MBPQS scheme.
	threads byte
}

// Allocates memory for a Context and sets the given parameters in it.
func newContext(p Params) (ctx *Context, err error) {
	ctx = new(Context)
	if p.n != 32 {
		return nil, fmt.Errorf("Only n=32 is supported for now (it was %d)", p.n)
	}
	ctx.params = p
	return ctx, nil
}

// Derive a keypair given for a context and n-byte random seeds skSeed, pubSeed, and skPrf.
func (ctx *Context) deriveKeyPair(skSeed, skPrf, pubSeed []byte) (
	*PrivateKey, *PublicKey, error) {
	if len(pubSeed) != int(ctx.params.n) || len(skSeed) != int(ctx.params.n) || len(skPrf) != int(ctx.params.n) {
		return nil, nil, fmt.Errorf(
			"skPrf, skSeed and pubSeed should have length %d", ctx.params.n)
	}

	pad := ctx.newScratchPad()

	sk, err := ctx.newPrivateKey(pad, skSeed, pubSeed, skPrf, 0)
	if err != nil {
		return nil, nil, err
	}
	pk, err := sk.derivePublicKey()
	if err != nil {
		return nil, nil, err
	}
	return sk, pk, nil
}

// Generate a privateKey for a context and n-byte random seeds skSeed, pubSeed, and skPrf.
func (ctx *Context) newPrivateKey(pad scratchPad, skSeed, pubSeed, skPrf []byte, seqNo SignatureSeqNo) (*PrivateKey, error) {
	// Precompute the hashes before building a tree and getting the root.
	ph := ctx.precomputedHashes(pubSeed, skSeed)

	// Create a root tree and retrieve the root
	rtBuf := ctx.genRootTree(pad, ph)

	//TODO
	// rt := rt.getRoot()

	ret := PrivateKey{
		seqNo:   0,
		skSeed:  skSeed,
		skPrf:   skPrf,
		pubSeed: pubSeed,
		ctx:     ctx,
		ph:      ctx.precomputedHashes(pubSeed, skSeed),
	}

	return &ret, nil
}

//TODO
func (sk *PrivateKey) derivePublicKey() (*PublicKey, error) {
	return nil, nil
}
