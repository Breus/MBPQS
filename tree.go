package mbpqs

import (
	"crypto"
	"fmt"

	"github.com/Breus/mbpqs/wotsp"
)

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
	wotsOps := wotsp.Opts{
		Mode:        ctx.wotsMode,
		Address:     otsAddr,
		Concurrency: ctx.threads,
		crypto.Hash: 0,
	}
	pkBuf := pad.wotsPK()
	ctx.wotsPkGenInto(pad, otsAddr, wotsOps, pkBuf)
	return ctx.lTree(pad, pkBuf, lTreeAddr)
}

/* From here on, we define the scratchpad, created to avoid many memory allocations.
 * The scratchpad includes a buffer with memory allocated for various computations.
 * Furthermore, the buffer includes a hashScratchPad, which is used as scratchpad during hash operations.
 */

func (ctx *Context) newScratchPad() scratchPad {
	n := ctx.p.N
	pad := scratchPad{
		buf:  make([]byte, 10*n+64+ctx.p.N*ctx.wotsLen),
		n:    n,
		hash: ctx.newHashScratchPad(),
	}
	return pad
}

func (ctx *Context) newScratchPad() scratchPad {
	return scratchPad{
		n:   ctx.params.n,
		buf: make([]byte, ctx.wotsParams.L*ctx.params.n),
	}
}

func (pad scratchPad) fBuf() []byte {
	return pad.buf[:3*pad.n]
}

func (pad scratchPad) hBuf() []byte {
	return pad.buf[3*pad.n : 7*pad.n]
}

func (pad scratchPad) prfBuf() []byte {
	return pad.buf[7*pad.n : 9*pad.n+32]
}

func (pad scratchPad) prfAddrBuf() []byte {
	return pad.buf[9*pad.n+32 : 9*pad.n+64]
}

func (pad scratchPad) wotsSkSeedBuf() []byte {
	return pad.buf[9*pad.n+64 : 10*pad.n+64]
}

func (pad scratchPad) wotsBuf() []byte {
	return pad.buf[10*pad.n+64:]
}
