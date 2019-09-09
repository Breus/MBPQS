package mbpqs

// rootTree is a MBPQS merkle root tree represented as an array.
type rootTree struct {
	H   uint32
	n   uint32
	buf []byte
}

// Generate the root tree by computing WOTS keypairs from the otsSeed and then hashing up.
func (ctx *Context) genRootTree(otsSeed, pubSeed []byte) rootTree {
	rt := newRootTree(ctx.params.H, ctx.params.n)
	ctx.genRootTreeInto(otsSeed, ctx.precomputeHashes(pubSeed, skSeed), rt)
	return rt
}

// Allocates memory for a merkle tree of n-byte string of height H.
func newRootTree(H, n uint32) rootTree {
	buf := make([]byte, (1<<height)*n)
	return rootTree{
		H:   H,
		n:   n,
		buf: buf,
	}
}

func (ctx *Context) genRootTreeInto(otsSeed
