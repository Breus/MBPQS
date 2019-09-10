package mbpqs

import "fmt"

// rootTree is a MBPQS merkle root tree represented as an array.
type rootTree struct {
	H   uint32
	n   uint32
	buf []byte
}

// To avoid constant memory allocations when computing the rootTree,
// goroutines use a scratchpad.
type scratchPad struct {
	n   uint32
	buf []byte
}

// Allocates memory for a merkle tree of n-byte string of height H.
func newRootTree(H, n uint32) rootTree {
	buf := make([]byte, ((1<<(H+1))-1)*n)
	return rootTree{
		H:   H,
		n:   n,
		buf: buf,
	}
}

// Generate the root tree by computing WOTS keypairs from the otsSeed and then hashing up.
func (ctx *Context) genRootTree(pad scratchPad, otsSeed, pubSeed []byte) rootTree {
	rt := newRootTree(ctx.params.rootH, ctx.params.n)
	ctx.genRootTreeInto(pad, otsSeed, pubSeed, rt)
	return rt
}

// Generate a root tree into the allocated memory rt.
func (ctx *Context) genRootTreeInto(pad scratchPad, otsSeed, pubSeed []byte, rt rootTree) {
	fmt.Println("Generating Root Tree..")
	var otsAddr, lTreeAddr, treeAddr address
	// Computing the leafs.
	var idx uint32
	if ctx.threads == 1 {
		for idx = 0; idx < (1 << ctx.params.rootH); idx++ {
			lTreeAddr.setLTree(idx)
			otsAddr.setOTS(idx)
			copy(rt.node(0, idx), ctx.genLeaf(pad, otsSeed, lTreeAddr, otsAddr))
		}
	}
}

// Returns a slice of the node at given height and index idx.
func (rt *rootTree) node(height, idx uint32) []byte {
	ptr := rt.n * ((1<<rt.H + 1) - (1 << (rt.H + 1 - height)) + idx)
	return rt.buf[ptr : ptr+rt.n]
}

// Generate the leaf by computing a WOTS key pair with the otsAddr and then
// a leaf using the lTreeAddr.
func (ctx *Context) genLeaf(pad scratchPad, otsS []byte, lTreeAddr, otsAddr address) []byte {
	pkBuf := pad.wotsPK()
	ctx.wotsPkGenInto(pad, otsAddr, pkBuf)
}


func (ctx *Context) wotsPkGenInto(pad scratchpad, otsAddr address, buf []byte){
	wotsp.GenPublicKey(ctx.)	
}

/* From this part, we define the scratchpad methods.
 * The scratchpad is ordered as follows:
 * wotsPublicKey (l*n) ||
 */
func (ctx *Context) newScratchPad() scratchPad {
	return scratchPad{
		n:   ctx.params.n,
		buf: make([]byte, ctx.wotsParams.L*ctx.params.n),
	}
}

// Get the slice of the scratchPad for the public-key part.
func (pad scratchPad) wotsPK() {
	return pad.buf[:]
}
