package mbpqs

// Params includes the MBPQS parameters.
type Params struct {
	n     uint32 // the security parameter, length of message digest and three nodes in bytes.
	rootH uint32 // the height of the three (# levels -1).
	w     uint16 // the Winternitz parameter, used in WOTS-T.
	ge    uint32 // the chain tree height growing exponent.
	chanH uint32 // the inital chain tree height.

}

var paramSets = []Params{
	Params{n: 32, rootH: 10, w: 16, ge: 1, chanH: 1},
	Params{n: 32, rootH: 16, w: 16, ge: 1, chanH: 1},
	Params{n: 32, rootH: 20, w: 16, ge: 1, chanH: 1},
	Params{n: 64, rootH: 10, w: 16, ge: 1, chanH: 1},
	Params{n: 64, rootH: 16, w: 16, ge: 1, chanH: 1},
}

// NewContextFromOid returns a new context for the given Root tree.
func NewContextFromOid(oid uint32) *Context {
	ctx, _ := newContext(paramSets[oid])
	return ctx
}

// Returns the 2log of the Winternitz parameter
func (params *Params) wotsLogW() uint8 {
	switch params.w {
	case 4:
		return 2
	case 16:
		return 4
	case 256:
		return 8
	default:
		panic("Only WotsW=4,16,256 are supported")
	}
}

// Returns the number of  main WOTS+ chains
func (params *Params) wotsLen1() uint32 {
	return 8 * params.n / uint32(params.wotsLogW())
}

// Returns the number of WOTS+ checksum chains
func (params *Params) wotsLen2() uint32 {
	switch params.w {
	case 4:
		return 2
	case 16:
		return 3
	case 256:
		return 5
	default:
		panic("Only WotsW=4,16,256 are supported")
	}
}

// Returns the total number of WOTS+ chains
func (params *Params) wotsLen() uint32 {
	return params.wotsLen1() + params.wotsLen2()
}

// Returns the size of a WOTS+ signature
func (params *Params) wotsSignatureSize() uint32 {
	return params.wotsLen() * params.n
}
