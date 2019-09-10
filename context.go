package mbpqs

import (
	"github.com/Breus/mbpqs/wotsp"
)

// MBPQS instance.
type Context struct {
	params Params // MBPQS parameters.
	/* WOTS-T Options, includes its Mode (includes parameters).
	 * Includes the OTS address, the concurrency settings, and the used hash function.
	 */
	opts wotsp.Opts
	// The amount of threads to use in the MBPQS scheme.
	threads byte
}

// Allocates memory for a Context and sets the given parameters in it.
func newContext(p Params) (ctx *Context, err error) {
	ctx = new(Context)
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
	return &sk, nil
}

//TODO
func (sk *PrivateKey) derivePublicKey() (*PublicKey, error) {
	return nil, nil
}
