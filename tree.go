package mbpqs

// rootTree is a MBPQS merkle root tree represented as an array.
type rootTree struct {
	height uint32
	n      uint32
	buf    []byte
}

func lTree(p *Param, wotsPk, pubSeed []byte, addr Address) []byte {
	return
}
