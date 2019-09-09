package mbpqs

import (
	"encoding/binary"
	"fmt"
)

const (
	OTS_ADDR_TYPE   = 0
	LTREE_ADDR_TYPE = 1
	TREE_ADDR_TYPE  = 2
)

// Address type for all address types.
type address [32]byte

/* Address field setters for all Address types.
 * First for OTS address, then LTREE address, then TREE address.
 */
func (addr *address) setLayer(layer uint32) {
	binary.BigEndian.PutUint32(addr[0:], layer)
}

func (addr *address) setTree(tree uint64) {
	binary.BigEndian.PutUint64(addr[4:], tree)
}

func (addr *address) setType(aType uint32) {
	binary.BigEndian.PutUint32(addr[12:], aType)
}

func (addr *address) setOTS(ots uint32) {
	binary.BigEndian.PutUint32(addr[16:], ots)
}

func (addr *address) setChain(chain uint32) {
	binary.BigEndian.PutUint32(addr[20:], chain)
}

func (addr *address) setHash(hash uint32) {
	binary.BigEndian.PutUint32(addr[24:], hash)
}

func (addr *address) setKeyAndMask(keyMask uint32) {
	binary.BigEndian.PutUint32(addr[28:], keyMask)
}

// Extra fields setters for LTREE addresses.
func (addr *address) setLTree(ltree uint32) {
	binary.BigEndian.PutUint32(addr[16:], ltree)
}

func (addr *address) setTreeHeight(height uint32) {
	binary.BigEndian.PutUint32(addr[20:], height)
}

func (addr *address) setTreeIndex(index uint32) {
	binary.BigEndian.PutUint32(addr[24:], index)
}

func (addr *address) toBytes() []byte {
	return addr[:]
}

func AddressFromBytes(data []byte) (addr address, err error) {
	if len(data) != 32 {
		err = fmt.Errorf("Given byte string must be 32 bytes, is %d instead.", len(data))
		return
	}
	copy(addr[:], data)
	return
}
