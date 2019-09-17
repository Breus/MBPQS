package mbpqs

import (
	"crypto/subtle"
	"fmt"
	"sync"
)

// SignatureSeqNo is the sequence number of signatures and wotsKeys.
// Should start at 0 to compute AuthPath and is synced with leaf index.
type SignatureSeqNo uint32

// RootSignature holds a signature on a channel by the rootTree.b
type RootSignature struct {
	ctx      *Context       // Defines the MBPQS instance which was used to create the Signature.
	seqNo    SignatureSeqNo // sequence number of this signature so you know which index key to verify.
	drv      []byte         // digest randomized value (r).
	wotsSig  []byte         // the WOTS signature over the channel root.
	authPath []byte         // the authentication path for this signature to the rootTree root node.

	chainSig []byte //

}

// ChainSignature is a signature over a chain tree root.
type ChainSignature struct {
	root  []byte
	index uint32
	layer uint32
}

// ChannelSignature holds a signature on a message in a channel.
type ChannelSignature struct {
	chIndex  uint32
	seqNo    SignatureSeqNo
	wotsSig  []byte // the WOTS signature over the channel message.
	authPath []byte // autpath to the rootSignature.
	drv      []byte // digest randomized value (r).
}

// Channel is a key channel within the MBPQS tree, are stacked chain trees with the same Tree address.
type Channel struct {
	idx    uint32         // The chIdx is the offset of the channel in the MBPQS tree.
	layers uint32         // The amount of chain layers in the channel.
	seqNo  SignatureSeqNo // The first signatureseqno available for signing in this channel.
	mux    sync.Mutex     // Used when mutual exclusion for the channel is required.
}

// PrivateKey is a MBPQS private key */
type PrivateKey struct {
	seqNo SignatureSeqNo // The seqNo of the first unused signing key.
	/* n-byte skSeed is used to pseudorandomly generate wots channelkeys seeds.
	 * S in RFC8931, SK_1 and S in XMSS-T paper.
	 */

	// Channels in the privatekey
	Channels []Channel

	skSeed []byte
	/* n-byte skPrf is used to randomize the message hash when signing.
	 * SK_PRF in RFC8931, SK_2 in XMSS-T paper.
	 */
	skPrf []byte
	/* n-byte pubSeed is used to randomize the hash to generate WOTS verification keys.
	 * SEED in RFC8931, SEED in XMSS-T paper.
	 */
	pubSeed []byte
	root    []byte            // n-byte root node of the root tree.
	ctx     *Context          // Context containing the MBPQS parameters.
	ph      precomputedHashes // Precomputed hashes from the pubSeed and skSeed.
	mux     sync.Mutex        // Used when mutual exclusion for the PrivateKey is required.
}

// PublicKey is a MBPQS public key.
type PublicKey struct {
	root []byte // n-byte root node of the root tree.
	/* n-byte pubSeed used to randomize the hash to generate WOTS verification keys.
	 * SEED in RFC8931, SEED in XMSS-T paper
	 */
	ph      precomputedHashes // Precomputed pubSeed hash.
	pubSeed []byte
	ctx     *Context // The context containing the algorithm definition for verifiers.
}

// InitParam returns a pointer to a Params struct with parameters initialized to given arguments.
func InitParam(n, rtH, chanH, ge uint32, w uint16) *Params {
	return &Params{
		n:     n,
		w:     w,
		rootH: rtH,
		chanH: chanH,
		ge:    ge,
	}
}

// GenerateKeyPair generates a new MBPQS keypair for given parameters.
func GenerateKeyPair(p *Params) (*PrivateKey, *PublicKey, error) {
	// Create new context including given parameters.
	ctx, err := newContext(*p)
	if err != nil {
		return nil, nil, err
	}

	// Set n-byte random seed values.
	skSeed, err := randomBytes(ctx.params.n)
	if err != nil {
		return nil, nil, err
	}
	skPrf, err := randomBytes(ctx.params.n)
	if err != nil {
		return nil, nil, err
	}
	pubSeed, err := randomBytes(ctx.params.n)
	if err != nil {
		return nil, nil, err
	}

	// Derive a keypair from the initialized Context.
	return ctx.deriveKeyPair(pubSeed, skSeed, skPrf)
}

// SignChannelRoot is used to sign the n-byte channel root hash with the PrivateKey
func (sk *PrivateKey) SignChannelRoot(chRt []byte) (*RootSignature, error) {
	// Create a new scratchpad to do the signing computations on to avoid memory allocations.
	pad := sk.ctx.newScratchPad()
	seqNo, err := sk.GetSeqNo()
	if err != nil {
		return nil, err
	}
	// Compute the digest randomized value (drv)
	drv := sk.ctx.prfUint64(pad, uint64(seqNo), sk.skPrf)
	// Hashed channelroot with H_msg
	hashChRt, err := sk.ctx.hashMessage(pad, chRt, drv, sk.root, uint64(seqNo))
	if err != nil {
		return nil, err
	}

	// Set otsAddr to calculate wotsSign over the message.
	var otsAddr address // All fields should be 0, that's why init is enough.
	// TODO: check address for OTS
	otsAddr.setOTS(uint32(seqNo)) // Except the OTS address which is seqNo = index.

	// Compute the root tree to build the authentication path
	rt := sk.ctx.genRootTree(pad, sk.ph)
	authPath := rt.AuthPath(uint32(seqNo))
	sig := RootSignature{
		ctx:      sk.ctx,
		seqNo:    seqNo,
		drv:      drv,
		wotsSig:  sk.ctx.wotsSign(pad, hashChRt, sk.pubSeed, sk.skSeed, otsAddr),
		authPath: authPath,
	}
	return &sig, nil
}

// VerifyChannelRoot is used to verify the signature on the channel root.
func (pk *PublicKey) VerifyChannelRoot(rtSig *RootSignature, chRt []byte) (bool, error) {
	// Create a new scratchpad to do the verifiyng computations on.
	pad := pk.ctx.newScratchPad()
	hashChRt, err := pk.ctx.hashMessage(pad, chRt, rtSig.drv, pk.root, uint64(rtSig.seqNo))
	if err != nil {
		return false, err
	}

	// Derive the wotsPk from the signature.
	var otsAddr address // all fields are 0, like they are supposed to.
	otsAddr.setOTS(uint32(rtSig.seqNo))

	// Create the wotsPk on the scratchpad.
	wotsPk := pad.wotsBuf()
	pk.ctx.wotsPkFromSigInto(pad, rtSig.wotsSig, hashChRt, pk.ph, otsAddr, wotsPk)

	// Create the leaf from the pk.
	var lTreeAddr address            // init with all fields 0.
	lTreeAddr.setType(lTreeAddrType) // Set address type.
	lTreeAddr.setLTree(uint32(rtSig.seqNo))
	curHash := pk.ctx.lTree(pad, wotsPk, pk.ph, lTreeAddr)

	// Now we use the authentication path to hash up to the root.
	var nodeAddr address
	var height uint32
	nodeAddr.setType(treeAddrType)

	index := uint32(rtSig.seqNo)
	for height = 1; height <= pk.ctx.params.rootH; height++ {
		nodeAddr.setTreeHeight(height - 1)
		nodeAddr.setTreeIndex(index >> 1)

		sibling := rtSig.authPath[(height-1)*pk.ctx.params.n : height*pk.ctx.params.n]

		var left, right []byte

		if index&1 == 0 {
			left = curHash
			right = sibling
		} else {
			left = sibling
			right = curHash
		}

		pk.ctx.hInto(pad, left, right, pk.ph, nodeAddr, curHash)
		index >>= 1
	}
	hashChRt = curHash

	if subtle.ConstantTimeCompare(hashChRt, pk.root) != 1 {
		return false, fmt.Errorf("invalid signature")
	}
	return true, nil
}

// GetSeqNo retrieves the current index of the first unusued channel signing key in the RootTree.
func (sk *PrivateKey) GetSeqNo() (SignatureSeqNo, error) {
	sk.mux.Lock()
	// Unlock the lock when the funtion is finished.
	defer sk.mux.Unlock()

	if uint64(sk.seqNo) == (1<<sk.ctx.params.rootH - 1) {
		return 0, fmt.Errorf("no unused signing keys left")
	}
	sk.seqNo++
	return sk.seqNo - 1, nil
}

// SignChannelMsg signs the message 'msg' in the channel with
func (sk *PrivateKey) SignChannelMsg(chIdx uint32, msg []byte) error /* ChannelSignature */ {
	if chIdx < uint32(len(sk.Channels)) { // Channel exists.
		//ch := sk.Channels[chIdx]

	} else if chIdx == uint32(len(sk.Channels)) { // Channel is the next available channel.
		// Scratchpad to avoid computation allocations.
		pad := sk.ctx.newScratchPad()
		// Create a new channel, because it does not exist yet.
		ch := sk.deriveChannel(chIdx)
		// Appending the created channel to the channellist in the PK.
		sk.Channels = append(sk.Channels, ch)
		// Create the first chainTree.
		ct := sk.genChainTree(chIdx, pad)
		// Get the root, and sign it.

		// Sign the root.

		// Construct the

	} else { // Channel does not exist, and it not the next available channel.
		return fmt.Errorf("channel %d does not exist, and is also not the next available channel", chIdx)
	}

	return nil
}
