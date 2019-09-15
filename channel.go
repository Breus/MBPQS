package mbpqs

// chainTree is a MBPQS chainTree represented as an array.
type chainTree struct {
	height uint32
	n      uint32
	buf    []byte
}

// deriveChannel creates a channel for chanelIdx.
func (ctx *Context) deriveChannel(channelIdx uint32) channel {
	// Create chainTree to retrieve the root from.
	//ct := ctx.genChainTree(channelIdx, 0)

	ret := channel{sigSeqNo: 0, chNo: ChannelIdx(channelIdx), root: []byte("hi")}

	return ret
}

func (ctx *Context) genChainTree(channelIdx uint32, chainLvl uint32) chainTree {
	height := channelIdx * uint32(ctx.params.ge) * ctx.params.chanH
	n := ctx.params.n
	ct := newChainTree(height, n)
	return ct
}

// Allocates memory for a chain tree of n-byte strings with height-1
func newChainTree(height, n uint32) chainTree {
	return chainTreeFromBuf(make([]byte, (2*height*n)), height, n)
}

// Makes a chain tree from a buffer.
func chainTreeFromBuf(buf []byte, height, n uint32) chainTree {
	return chainTree{
		height: height,
		n:      n,
		buf:    buf,
	}
}
