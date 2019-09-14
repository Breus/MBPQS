package mbpqs

// The Winternitz One-Time Signature scheme as used by MBPQS.

// Generate WOTS+ secret key
func (ctx *Context) genWotsSk(pad scratchPad, ph precomputedHashes,
	addr address, out []byte) {
	var i uint32
	addr.setChain(0)
	addr.setHash(0)
	addr.setKeyAndMask(0)
	buf := pad.wotsSkSeedBuf()
	ph.prfAddrSkSeedInto(pad, addr, buf)
	for i = 0; i < ctx.wotsLen; i++ {
		ctx.prfUint64Into(pad, uint64(i), buf, out[i*ctx.params.n:])
	}
}

// Converts a message into positions on the WOTS+ chains, which
// are called "chain lengths".
func (ctx *Context) wotsChainLengths(msg []byte) []uint8 {
	ret := make([]uint8, ctx.wotsLen)

	// compute the chain lengths for the message itself
	ctx.toBaseW(msg, ret[:ctx.wotsLen1])

	// compute the checksum
	var csum uint32 // = 0 init
	for i := 0; i < int(ctx.wotsLen1); i++ {
		csum += uint32(ctx.params.w) - 1 - uint32(ret[i])
	}
	csum = csum << (8 - ((ctx.wotsLen2 * uint32(ctx.wotsLogW)) % 8))

	// put checksum in buffer
	ctx.toBaseW(
		encodeUint64(
			uint64(csum),
			int((ctx.wotsLen2*uint32(ctx.wotsLogW)+7)/8)),
		ret[ctx.wotsLen1:])
	return ret
}

// Converts the given array of bytes into base w for the WOTS+ one-time
// signature scheme.  Only works if LogW divides into 8.
func (ctx *Context) toBaseW(input []byte, output []uint8) {
	if ctx.params.w == 256 {
		copy(output, input)
		return
	}

	var in uint32  // = 0 init
	var out uint32 // = 0 init
	var total uint8
	var bits uint8

	for consumed := 0; consumed < len(output); consumed++ {
		if bits == 0 {
			total = input[in]
			in++
			bits = 8
		}
		bits -= ctx.wotsLogW
		output[out] = uint8(uint16(total>>bits) & (ctx.params.w - 1))
		out++
	}
}

// Compute the (start + steps)th value in the WOTS+ chain, given
// the start'th value in the chain.
func (ctx *Context) wotsGenChainInto(pad scratchPad, in []byte,
	start, steps uint16, ph precomputedHashes, addr address, out []byte) {
	copy(out, in)
	var i uint16
	for i = start; i < (start+steps) && (i < ctx.params.w); i++ {
		addr.setHash(uint32(i))
		ctx.fInto(pad, out, ph, addr, out)
	}
}

// Generate a WOTS+ public key from secret key seed.
func (ctx *Context) wotsPkGen(pad scratchPad, ph precomputedHashes,
	addr address) []byte {
	ret := make([]byte, ctx.wotsLen*ctx.params.n)
	ctx.wotsPkGenInto(pad, ph, addr, ret)
	return ret
}

// Generate a WOTS+ public key from secret key seed.
func (ctx *Context) wotsPkGenInto(pad scratchPad, ph precomputedHashes,
	addr address, out []byte) {
	ctx.genWotsSk(pad, ph, addr, out)
	var i uint32
	for i = 0; i < ctx.wotsLen; i++ {
		addr.setChain(uint32(i))
		ctx.wotsGenChainInto(pad, out[ctx.params.n*i:ctx.params.n*(i+1)],
			0, ctx.params.w-1, ph, addr,
			out[ctx.params.n*i:ctx.params.n*(i+1)])
	}
}

// Create a WOTS+ signature of a n-byte message
func (ctx *Context) wotsSign(pad scratchPad, msg, pubSeed, skSeed []byte,
	addr address) []byte {
	ret := make([]byte, ctx.wotsSigBytes)
	ctx.wotsSignInto(pad, msg, ctx.precomputeHashes(pubSeed, skSeed), addr, ret)
	return ret
}

// Create a WOTS+ signature of a n-byte message
func (ctx *Context) wotsSignInto(pad scratchPad, msg []byte,
	ph precomputedHashes, addr address, wotsSig []byte) {
	lengths := ctx.wotsChainLengths(msg)
	ctx.genWotsSk(pad, ph, addr, wotsSig)
	var i uint32
	for i = 0; i < ctx.wotsLen; i++ {
		addr.setChain(uint32(i))
		ctx.wotsGenChainInto(pad, wotsSig[ctx.params.n*i:ctx.params.n*(i+1)],
			0, uint16(lengths[i]), ph, addr,
			wotsSig[ctx.params.n*i:ctx.params.n*(i+1)])
	}
}

// Computes the public key from a message and its WOTS+ signature and
// stores it in the provided buffer.
func (ctx *Context) wotsPkFromSigInto(pad scratchPad, sig, msg []byte,
	ph precomputedHashes, addr address, pk []byte) {
	lengths := ctx.wotsChainLengths(msg)
	var i uint32
	for i = 0; i < ctx.wotsLen; i++ {
		addr.setChain(uint32(i))
		ctx.wotsGenChainInto(pad, sig[ctx.params.n*i:ctx.params.n*(i+1)],
			uint16(lengths[i]), ctx.params.w-1-uint16(lengths[i]),
			ph, addr, pk[ctx.params.n*i:ctx.params.n*(i+1)])
	}
}

// Returns the public key from a message and its WOTS+ signature.
func (ctx *Context) wotsPkFromSig(pad scratchPad, sig, msg []byte,
	ph precomputedHashes, addr address) []byte {
	pk := make([]byte, ctx.params.n*ctx.wotsLen)
	ctx.wotsPkFromSigInto(pad, sig, msg, ph, addr, pk)
	return pk
}
