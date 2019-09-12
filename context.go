package mbpqs

import (
	"fmt"
)

// Context including a full MBPQS instance.
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
func newContext(p *Params) (ctx *Context, err error) {
	ctx = new(Context)
	if p.n != 32 {
		return nil, fmt.Errorf("Only n=32 is supported for now (it was %d)", p.n)
	}
	ctx.params = *p
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
	pk := sk.derivePublicKey()
	if err != nil {
		return nil, nil, err
	}
	return sk, pk, nil
}

// Generate a privateKey for a context and n-byte random seeds skSeed, pubSeed, and skPrf.
func (ctx *Context) newPrivateKey(pad scratchPad, skSeed, pubSeed, skPrf []byte, seqNo SignatureSeqNo) (*PrivateKey, error) {
	ret := PrivateKey{
		seqNo:   0,
		skSeed:  skSeed,
		skPrf:   skPrf,
		pubSeed: pubSeed,
		ctx:     ctx,
		ph:      ctx.precomputeHashes(pubSeed, skSeed),
	}

	// Create a root tree to retrieve the root.
	rt := ctx.genRootTree(pad, ret.ph)

	ret.root = make([]byte, ctx.params.n)
	copy(ret.root, rt.getRootNode())

	return &ret, nil
}

// Return the MBPQS PublicKey derived from this PrivateKey.
func (sk *PrivateKey) derivePublicKey() *PublicKey {
	ret := PublicKey{
		ctx:     sk.ctx,
		pubSeed: sk.pubSeed,
		ph:      sk.ctx.precomputeHashes(sk.pubSeed, nil),
		root:    sk.root,
	}
	return &ret
}
