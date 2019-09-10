package mbpqs

import (
	"fmt"

	"github.com/Breus/mbpqs/wotsp"
)

// MBPQS instance.
type Context struct {
	params Params // MBPQS parameters.
	/* WOTS-T Options, includes its Mode (includes parameters).
	 * Includes the OTS address, the concurrency settings, and the used hash function.
	 */

	/* WOTS-T mode, concurrency is already in threads,
	 */
	wotsMode   wotsp.Mode
	wotsParams wotsp.Params
	// The amount of threads to use in the MBPQS scheme.
	threads byte
}

// Allocates memory for a Context and sets the given parameters in it.
func newContext(p Params) (ctx *Context, err error) {
	ctx = new(Context)
	if p.n != 32 {
		return nil, fmt.Errorf("Only n=32 is supported for now (it was %d)", p.n)
	}
	switch p.w {
	case 4:
		ctx.wotsMode = 0
	case 16:
		ctx.wotsMode = 1
	case 256:
		ctx.wotsMode = 2
	default:
		return nil, fmt.Errorf("Please chose w from the {4,16,256} (it was %d)", p.w)
	}
	ctx.params = p
	ctx.wotsParams = ctx.wotsMode.Params()
	return ctx, nil
}

// Derive a keypair given for a context and n-byte random seeds otsSeed, pubSeed, and msgSeed.
func (ctx *Context) deriveKeyPair(otsSeed, pubSeed, msgSeed []byte) (
	*PrivateKey, *PublicKey, error) {
	pad := ctx.newScratchPad()

	sk, err := ctx.newPrivateKey(pad, otsSeed, pubSeed, msgSeed)
	if err != nil {
		return nil, nil, err
	}
	pk, err := sk.derivePublicKey()
	if err != nil {
		return nil, nil, err
	}
	return sk, pk, nil
}

// Generate a privateKey for a context and n-byte random seeds otsSeed, pubSeed, and msgSeed.
func (ctx *Context) newPrivateKey(pad scratchPad, otsSeed, pubSeed, msgSeed []byte) (*PrivateKey, error) {
	sk := PrivateKey{
		rootIdx: 0,
		otsSeed: otsSeed,
		pubSeed: pubSeed,
		msgSeed: msgSeed,
		ctx:     ctx,
	}
	return &sk, nil
}

//TODO
func (sk *PrivateKey) derivePublicKey() (*PublicKey, error) {
	return nil, nil
}
