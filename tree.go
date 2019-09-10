package mbpqs

// rootTree is a MBPQS merkle root tree represented as an array.
type rootTree struct {
	H   uint32
	n   uint32
	buf []byte
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

// Generate the root tree by computing WOTS keypairs from the otsSeed and then hashing up.
func (ctx *Context) genRootTree(otsSeed, pubSeed []byte) rootTree {
	rt := newRootTree(ctx.params.H, ctx.params.n)
	ctx.genRootTreeInto(otsSeed, pubSeed, rt)
	return rt
}

func (ctx *Context) genRootTreeInto(otsSeed, pubSeed, rt) {
	log.LogF("Generating Root Tree")

	var otsAddr, lTreeAddr, treeAddr address
	// Computing the leafs.
	var idx uint32
	if ctx.threads == 1 {
		for idx = 0; idx < (1 << ctx.H); idx++ {
			lTreeAddr.setLTree(idx)
			otsAddr.setOTS(idx)
			copy(mt.Node(0, idx), ctx.genLeaf(otsSeed, lTreeAddr, otsAddr))
		}
	}
}

// Returns a slice of the node at given height and index idx.
func (rt *rootTree) Node(height, idx uint32) []byte {
	ptr := rt.n * ((1 << rt.height) - (1 << (rt.height - height)) + idx)
	return rt.buf[ptr : ptr+rt.n]
}
