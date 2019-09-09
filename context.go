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
	opts wotsp.Opts
}

func newContext(p Params) (ctx *Context, err error) {
	ctx = new(Context)
	if p.n != 32 {
		return nil, fmt.Errorf("Only n=32 is supported for now (it was %d)", p.n)
	}
	switch p.w {
	case 4:
		ctx.opts.Mode = 0
	case 16:
		ctx.opts.Mode = 1
	case 256:
		ctx.opts.Mode = 2
	default:
		return nil, fmt.Errorf("Please chose w from the {4,16,256} (it was %d)", p.w)
	}
	ctx.params = p
	return ctx, nil
}

// Derive a keypair given for a context and n-byte random seeds otsSeed, pubSeed, and msgSeed.
func (ctx *Context) DeriveKeyPair(otsSeed, pubSeed, msgSeed []byte, err error) (
	*PrivateKey, *PublicKey, error) {
	sk, err := ctx.newPrivateKey(otsSeed, pubSeed, msgSeed)
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
func (ctx *Context) newPrivateKey(otsSeed, pubSeed, msgSeed []byte) (*PrivateKey, error) {
	sk := PrivateKey{
		rootIdx: 0,
		otsSeed: otsSeed,
		pubSeed: pubSeed,
		msgSeed: msgSeed,
		ctx:     ctx,
	}
	return sk, nil
}

func (sk *PrivateKey) derivePublicKey() (*PublicKey, error) {
	return
}
