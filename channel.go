package mbpqs

import (
	"crypto/subtle"
	"fmt"
	"runtime"
	"sync"
)

/* Represents a height t chainTree of n-byte string nodes N[i,j] as:
 					N[t-1,0]
					/	 |
			  N(t-2,1)  N(t-2,1) (t-2 - t-2 = 0)
				/ |
			   (...)
			  /	  |
	      N(1,0) N(1,1) (id: t-2-1)
		  /	  |
(t-1) N(0,0) N(0,1) (id: t-2-0)


	The buf array is structered as follows:
	[(0,0),(0,1),(1,0)(1,1),(...),(t-2,0)(t-2,1),(t-1,0)]
*/

type chainTree struct {
	height uint32
	n      uint32
	buf    []byte
}

// DeriveChannel creates a channel for chanelIdx.
func (sk *PrivateKey) deriveChannel(chIdx uint32) *Channel {
	return &Channel{
		layers:     0,
		chainSeqNo: 0,
		seqNo:      0,
	}
}

// Allocates a new ChainTree and returns a generated chaintree into the memory.
func (sk *PrivateKey) genChainTree(pad scratchPad, chIdx, chLayer uint32) chainTree {
	ct := newChainTree(sk.ctx.chainTreeHeight(chLayer), sk.ctx.params.n)
	sk.genChainTreeInto(pad, chIdx, chLayer, ct)
	return ct
}

// Generates a chain tree into ct.
func (sk *PrivateKey) genChainTreeInto(pad scratchPad, chIdx, chLayer uint32, ct chainTree) {
	// Init addresses for OTS, LTree nodes, and Tree nodes.
	var otsAddr, lTreeAddr, nodeAddr address
	sta := SubTreeAddress{
		Layer: chLayer,
		Tree:  uint64(chIdx),
	}

	addr := sta.address()
	otsAddr.setSubTreeFrom(addr)
	lTreeAddr.setSubTreeFrom(addr)
	lTreeAddr.setType(lTreeAddrType)
	nodeAddr.setSubTreeFrom(addr)
	nodeAddr.setType(treeAddrType)
	// First, compute the leafs of the chain tree.
	var idx uint32
	if sk.ctx.threads == 1 {
		// No. leafs == height of the chain tree.
		for idx = 0; idx < ct.height; idx++ {
			lTreeAddr.setLTree(idx)
			otsAddr.setOTS(idx)
			copy(ct.leaf(idx), sk.ctx.genLeaf(pad, sk.ph, lTreeAddr, otsAddr))
		}
	} else {
		// The code in this branch does exactly the same as in the
		// branch above, but in parallel.
		wg := &sync.WaitGroup{}
		mux := &sync.Mutex{}
		var perBatch uint32 = 32
		threads := sk.ctx.threads
		if threads == 0 {
			threads = runtime.NumCPU()
		}
		wg.Add(threads)
		for i := 0; i < threads; i++ {
			go func(lTreeAddr, otsAddr address) {
				pad := sk.ctx.newScratchPad()
				var ourIdx uint32
				for {
					mux.Lock()
					ourIdx = idx
					idx += perBatch
					mux.Unlock()
					if ourIdx >= ct.height {
						break
					}
					ourEnd := ourIdx + perBatch
					if ourEnd > ct.height {
						ourEnd = ct.height
					}
					for ; ourIdx < ourEnd; ourIdx++ {
						lTreeAddr.setLTree(ourIdx)
						otsAddr.setOTS(ourIdx)
						copy(ct.leaf(ourIdx), sk.ctx.genLeaf(
							pad,
							sk.ph,
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
	// Looping through all the layers of the chainTree.
	for height = 1; height < ct.height; height++ {
		// Set tree height of the computed node.
		nodeAddr.setTreeHeight(height - 1)
		// Internal nodes and root node have Treeindex 0.
		nodeAddr.setTreeIndex(0)
		sk.ctx.hInto(pad, ct.node(height-1, 0), ct.node(height-1, 1), sk.ph, nodeAddr, ct.node(height, 0))
	}
}

// Returns a slice of the leaf at given leaf index.
func (ct *chainTree) leaf(idx uint32) []byte {
	if idx == ct.height-1 {
		return ct.node(0, 0)
	}

	h := ct.height - 2 - idx
	return ct.node(h, 1)
}

// Returns a slice of the node at given height and index idx in the chain tree.
func (ct *chainTree) node(height, idx uint32) []byte {
	ptr := ct.n * (2*height + idx)
	return ct.buf[ptr : ptr+ct.n]
}

// Gets the root node of the chain tree.
func (ct *chainTree) getRootNode() []byte {
	return ct.node(ct.height-1, 0)
}

// Allocates memory for a chain tree of n-byte strings with height-1.
func newChainTree(height, n uint32) chainTree {
	return chainTreeFromBuf(make([]byte, (2*height-1)*n), height, n)
}

// Makes a chain tree from a buffer.
func chainTreeFromBuf(buf []byte, height, n uint32) chainTree {
	return chainTree{
		height: height,
		n:      n,
		buf:    buf,
	}
}

// Returns the height of a chain tree at layer chainLayer.
func (ctx *Context) chainTreeHeight(chainLayer uint32) uint32 {
	return ctx.params.chanH + ctx.params.gf*(chainLayer-1)
}

// ChainSeqNo retrieves the current cahinSeqNo and increases it with one.
func (sk *PrivateKey) ChainSeqNo(chIdx uint32) uint32 {
	ch := sk.getChannel(chIdx)
	ch.mux.Lock()
	ch.chainSeqNo++
	ch.mux.Unlock()
	return ch.chainSeqNo - 1

}

// ChannelSeqNos retrieves the current chainSeqNo and the current channelSeqNo.
func (sk *PrivateKey) ChannelSeqNos(chIdx uint32) (uint32, SignatureSeqNo, error) {
	ch := sk.getChannel(chIdx)
	ch.mux.Lock()
	// Unlock the lock when the function is finished.
	defer ch.mux.Unlock()
	ch.chainSeqNo++
	if uint32(ch.seqNo) == ^uint32(0) {
		return 0, 0, fmt.Errorf("Please use a new key channel, this one has used the maximum of keys (2^32)")
	}

	ch.seqNo++
	return ch.chainSeqNo - 1, ch.seqNo - 1, nil
}

// Returns the layer of the current chain in the channel.
func (sk *PrivateKey) getChannelLayer(chIdx uint32) uint32 {
	return sk.getChannel(chIdx).layers
}

// Retrieve the authpath, calculated from the amount of available keys.
func (ct *chainTree) authPath(sig uint32) []byte {
	// For last key in a chainTree, autpath is the right node,
	// thus index = 1 on bottom level (height=0).
	if sig == ct.height-1 {
		return ct.node(0, 1)
	}
	// For the rest, authpath is alway the left node in the tree, thus index = 0.
	return ct.node(ct.height-2-sig, 0)
}

// Get node height of a node on chainLayer with chainSeqNo chainSeqNo.
func (ctx *Context) getNodeHeight(chainLayer, chainSeqNo uint32) uint32 {
	chainHeight := ctx.chainTreeHeight(chainLayer)
	if chainHeight-1 == chainSeqNo {
		return 0
	}
	return chainHeight - 2 - chainSeqNo
}

// Returns the channel on index input.
func (sk *PrivateKey) getChannel(chIdx uint32) *Channel {
	return sk.Channels[chIdx]
}

// GrowChannel creates a GrowSignature for channel chIdx with the root of the next chainTree embedded.
func (sk *PrivateKey) growChannel(chIdx uint32) (*GrowSignature, error) {
	// Returns an error if the channel does not exist.
	if chIdx > uint32(len(sk.Channels)) {
		return nil, fmt.Errorf("channel does not exist, please create it first")
	}

	// Check if last key of a chaintree is used to sign a new chain tree.
	ch := sk.getChannel(chIdx)
	if !(sk.ctx.chainTreeHeight(ch.layers)-1 == uint32(ch.chainSeqNo)) {
		return nil, fmt.Errorf("current chainTree hasn't used its full capacity yet")
	}

	// Compute the new tree, and retrieve its root node.
	pad := sk.ctx.newScratchPad()
	ct := sk.genChainTree(pad, chIdx, ch.layers+1)
	ctRoot := ct.getRootNode()

	// Retrieve and update chainSeqNo.
	chainSeqNo := sk.ChainSeqNo(chIdx)

	// Set OTSaddr to calculate the Wots sig over the message.
	var otsAddr address
	otsAddr.setOTS(uint32(chainSeqNo))
	otsAddr.setLayer(ch.layers)
	otsAddr.setTree(uint64(chIdx))

	// These fields can only be set after check for required rootSignature is made.
	sig := &GrowSignature{
		ctx:        sk.ctx,
		chainSeqNo: chainSeqNo,
		chIdx:      chIdx,
		layer:      ch.layers,
		wotsSig:    sk.ctx.wotsSign(pad, ctRoot, sk.pubSeed, sk.skSeed, otsAddr),
		rootHash:   ctRoot,
	}

	// Update the channel information for an additional tree.
	ch.layers++
	ch.chainSeqNo = 0
	return sig, nil
}

// Verify a chainTree root signature, part of the growsignature.
func (pk *PublicKey) verifyChainTreeRoot(sig *GrowSignature,
	authNode []byte) (bool, error) {
	pad := pk.ctx.newScratchPad()

	sta := SubTreeAddress{
		Layer: sig.layer,
		Tree:  uint64(sig.chIdx),
	}
	addr := sta.address()
	var otsAddr address
	otsAddr.setSubTreeFrom(addr)
	otsAddr.setOTS(uint32(sig.chainSeqNo))
	wotsPk := pad.wotsBuf()
	pk.ctx.wotsPkFromSigInto(pad, sig.wotsSig, sig.rootHash, pk.ph, otsAddr, wotsPk)

	// Compute the leaf from the wotsPk.
	var lTreeAddr address
	lTreeAddr.setSubTreeFrom(addr)
	lTreeAddr.setType(lTreeAddrType)
	lTreeAddr.setLTree(uint32(sig.chainSeqNo))
	curHash := pk.ctx.lTree(pad, wotsPk, pk.ph, lTreeAddr)

	if subtle.ConstantTimeCompare(curHash, authNode) != 1 {
		return false, nil
	}
	return true, nil

}
