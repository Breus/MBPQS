package mbpqs

import (
	"fmt"
	"sync"
)

// SignatureSeqNo is the sequence number of signatures.
// Should start at 0 to compute AuthPath and is synced with leaf index.
type SignatureSeqNo uint32

// RootSignature holds a signature on a channel by the rootTree.b
type RootSignature struct {
	ctx      *Context       // Defines the MBPQS instance which was used to create the Signature.
	seqNo    SignatureSeqNo // sequence number of this signature so you know which index key to verify.
	drv      []byte         // digest randomized value (r).
	wotsSig  []byte         // the WOTS signature over the message.
	authPath []byte         // the authentication path for this signature to the rootTree root node.
}

// PrivateKey is a MBPQS private key */
type PrivateKey struct {
	seqNo SignatureSeqNo // The seqNo of the first unused signing key.
	/* n-byte skSeed is used to pseudorandomly generate wots channelkeys seeds.
	 * S in RFC8931, SK_1 and S in XMSS-T paper.
	 */
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
	mux     sync.Mutex        // Used when mutual exclusion for the PrivateKey
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

// Return a pointer to a Params struct with parameters initialized to given arguments.
func initParam(n, rtH, chanH, d uint32, w uint16) *Params {
	return &Params{
		n:         n,
		w:         w,
		rootH:     rtH,
		initChanH: chanH,
		d:         d,
	}
}

// GenerateKeyPair generates a new MBPQS keypair for given parameters.
func GenerateKeyPair(p Params) (*PrivateKey, *PublicKey, error) {
	// Create new context including given parameters.
	ctx, err := newContext(p)
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
func (sk *PrivateKey) SignChannelRoot(msg []byte) (*RootSignature, error) {
	// Create a new scratchpad to do the signing computations on to avoid memory allocations.
	pad := sk.ctx.newScratchPad()
	seqNo, err := sk.GetSeqNo()
	if err != nil {
		return nil, err
	}

	// Set otsAddr to calculate wotsSign over the message.
	var otsAddr address
	// TODO: define right address
	otsAddr.setLayer(1) // 1 for root tree?
	otsAddr.setTree(uint64(seqNo))

	// Compute the root tree to build the authentication path
	rt := sk.ctx.genRootTree(pad, sk.ph)
	authPath := rt.AuthPath(uint32(seqNo))

	sig := RootSignature{
		ctx:      sk.ctx,
		seqNo:    seqNo,
		drv:      sk.ctx.prfUint64(pad, uint64(seqNo), sk.skPrf),
		wotsSig:  sk.ctx.wotsSign(pad, msg, sk.pubSeed, sk.skSeed, otsAddr),
		authPath: authPath,
	}

	return &sig, nil
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
