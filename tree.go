package mbpqs

import (
	"fmt"
	"runtime"
	"sync"
)

// SubTreeAddress represents the position of a subtree in the full MBPQS tree.
type SubTreeAddress struct {
	// The root tree has layer 0.
	// The top-level chain tree has layer 1, etc.
	Layer uint32

	// The offset in the subtree.
	// The root has tree index = 0.
	// The leftmost chaintrees have tree = 0.
	Tree uint64
}

// rootTree is a MBPQS merkle root tree represented as an array.
type rootTree struct {
	height uint32
	n      uint32
	buf    []byte
}

// To avoid constant memory allocations when computing the rootTree,
// goroutines use a scratchpad.
type scratchPad struct {
	n   uint32
	buf []byte
	// The scratchPad has a hashScratchPad to avoid memory allocations during hash computations.
	hashPad hashScratchPad
}

// Allocates memory for a root tree of n-byte string with heigth-1 height.
func newRootTree(height, n uint32) rootTree {
	return rootTreeFromBuf(make([]byte, ((1<<height)-1)*n), height, n)
}

// Makes a root tree from a buffer.
func rootTreeFromBuf(buf []byte, height, n uint32) rootTree {
	return rootTree{
		height: height,
		n:      n,
		buf:    buf,
	}
}

// Gets the root node of the root tree.
func (rt *rootTree) getRootNode() []byte {
	return rt.node(rt.height-1, 0)
}

// Generate the root tree by computing WOTS keypairs from the skSeed and then hashing up.
func (ctx *Context) genRootTree(pad scratchPad, ph precomputedHashes) rootTree {
	rt := newRootTree(ctx.params.rootH+1, ctx.params.n)
	ctx.genRootTreeInto(pad, ph, rt)
	return rt
}

//TODO Generate a root tree into the allocated memory rt.
func (ctx *Context) genRootTreeInto(pad scratchPad, ph precomputedHashes, rt rootTree) {
	fmt.Println("Generating Root Tree..")

	// Init address for OTS, LTree nodes, and Tree nodes.
	var otsAddr, lTreeAddr, nodeAddr address

	// Set subTreeAddress for the
	rta := SubTreeAddress{
		Layer: 0,
		Tree:  0,
	}
	addr := rta.address()
	otsAddr.setSubTreeFrom(addr)
	otsAddr.setType(otsAddrType)
	lTreeAddr.setSubTreeFrom(addr)
	lTreeAddr.setType(lTreeAddrType)
	nodeAddr.setSubTreeFrom(addr)
	nodeAddr.setType(treeAddrType)

	// First, compute the leafs of the tree.
	var idx uint32

	if ctx.threads == 1 {
		for idx = 0; idx < (1 << ctx.params.rootH); idx++ {
			lTreeAddr.setLTree(idx)
			otsAddr.setOTS(idx)
			copy(rt.node(0, idx), ctx.genLeaf(pad, ph, lTreeAddr, otsAddr))
		}
	} else {
		// The code in this branch does exactly the same as in the
		// branch above, but in parallel.
		wg := &sync.WaitGroup{}
		mux := &sync.Mutex{}
		var perBatch uint32 = 32
		threads := ctx.threads
		if threads == 0 {
			threads = runtime.NumCPU()
		}
		wg.Add(threads)

		for i := 0; i < threads; i++ {
			go func(lTreeAddr, otsAddr address) {
				pad := ctx.newScratchPad()
				var ourIdx uint32
				for {
					mux.Lock()
					ourIdx = idx
					idx += perBatch
					mux.Unlock()
					if ourIdx >= 1<<ctx.params.rootH {
						break
					}
					ourEnd := ourIdx + perBatch
					if ourEnd > 1<<ctx.params.rootH {
						ourEnd = 1 << ctx.params.rootH
					}
					for ; ourIdx < ourEnd; ourIdx++ {
						lTreeAddr.setLTree(ourIdx)
						otsAddr.setOTS(ourIdx)
						copy(rt.node(0, ourIdx), ctx.genLeaf(
							pad,
							ph,
							lTreeAddr,
							otsAddr))
					}
				}
				wg.Done()
			}(lTreeAddr, otsAddr)
		}
		wg.Wait()
	}

	// Next, compute the internal nodes and the root node.
	var height uint32
	// Looping through all the layers of the rootTree.
	for height = 1; height <= ctx.params.rootH; height++ {
		// Set tree height of the computed node
		nodeAddr.setTreeHeight(height - 1)
		// Looping through al the nodes on a rootTree layer.
		for idx = 0; idx < (1 << (ctx.params.rootH - height)); idx++ {
			nodeAddr.setTreeIndex(idx)
			// Hashing pairs of nodes on a layer into eachother.
			ctx.hInto(pad, rt.node(height-1, 2*idx),
				rt.node(height-1, 2*idx+1),
				ph, nodeAddr, rt.node(height, idx))
		}
	}
}

// Returns a slice of the node at given height and index idx.
func (rt *rootTree) node(height, idx uint32) []byte {
	ptr := rt.n * ((1 << rt.height) - (1 << (rt.height - height)) + idx)
	return rt.buf[ptr : ptr+rt.n]
}

// Generate the leaf by computing a WOTS key pair with the otsAddr and then
// a leaf using the lTreeAddr.
func (ctx *Context) genLeaf(pad scratchPad, ph precomputedHashes,
	lTreeAddr, otsAddr address) []byte {
	pk := pad.wotsBuf()
	ctx.wotsPkGenInto(pad, ph, otsAddr, pk)
	return ctx.lTree(pad, pk, ph, lTreeAddr)
}

// Computes the leaf node associated to a WOTS+ verification key.
// Note that the WOTS+ verification key is destroyed.
func (ctx *Context) lTree(pad scratchPad, wotsPk []byte, ph precomputedHashes, addr address) []byte {
	var height uint32 // = 0 Golang init.
	l := ctx.wotsLen  //uint32
	for l > 1 {
		addr.setTreeHeight(height)
		// Amount of parentnodes this node has: equal to amount of 'neightbour nodes'.
		parentNodes := l >> 1
		var i uint32
		// Go through all the nodes on the current lTree level.
		for i = 0; i < parentNodes; i++ {
			// Set the lTree index of the computed node
			addr.setTreeIndex(i)
			// Hash each wotsPk ellement with its neighbour element (node if heigher than level 1).
			ctx.hInto(pad, wotsPk[2*i*ctx.params.n:(2*i+1)*ctx.params.n],
				wotsPk[(2*i+1)*ctx.params.n:(2*i+2)*ctx.params.n],
				ph, addr,
				wotsPk[i*ctx.params.n:(i+1)*ctx.params.n])
		}
		// Check if l is uneven: then we need to elevate 1 node to a higher layer, because it has no neighbour node.
		if l&1 == 1 {
			copy(wotsPk[(l>>1)*ctx.params.n:((l>>1)+1)*ctx.params.n],
				wotsPk[(l-1)*ctx.params.n:l*ctx.params.n])
			l = (l >> 1) + 1
		} else { // If l = even, go to the next layer.
			l = l >> 1
		}
		// Set the new height level for the next layer level.
		height++
	}
	ret := make([]byte, ctx.params.n)
	// Copy the n-byte root leaf into the ret byte slice.
	copy(ret, wotsPk[:ctx.params.n])
	return ret
}

// Return the authentication path for the given leaf.
func (rt *rootTree) AuthPath(leaf uint32) []byte {
	ret := make([]byte, rt.n*(rt.height-1))
	node := leaf
	var i uint32
	for i = 0; i < rt.height-1; i++ {
		// node ^ 1 (bitwise xor) is the index offset of the sibling of node to pair with.
		test := rt.node(i, node^1)
		copy(ret[i*rt.n:], test)
		// node / 2 is the index offset of the parent of node on its layer.
		node = node / 2

	}
	return ret
}

/* From here on, we define the scratchpad, created to avoid many memory allocations.
 * The scratchpad includes a buffer with memory allocated for various computations.
 * Furthermore, the buffer includes a hashScratchPad, which is used as scratchpad during hash operations.
 */

func (ctx *Context) newScratchPad() scratchPad {
	n := ctx.params.n
	pad := scratchPad{
		buf:     make([]byte, 10*n+64+ctx.params.n*ctx.wotsLen),
		n:       n,
		hashPad: ctx.newHashScratchPad(),
	}
	return pad
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

/* ONLY FOR TESTING PURPOSES!!!
 *
 */

func (ctx *Context) getWotsSeed(pad scratchPad, ph precomputedHashes,
	addr address) []byte {
	addr.setChain(0)
	addr.setHash(0)
	addr.setKeyAndMask(0)
	ret := make([]byte, ctx.params.n)
	ph.prfAddrSkSeedInto(pad, addr, ret)
	return ret
}
