package mbpqs

// PrivateKey is a MBPQS private key */
type PrivateKey struct {
	// 4-byte rootIndex holds the index of the next available ChannelKey in the root tree. */
	rootIdx uint32
	/* n-byte wotsSeed is used to pseudorandomly generate wots channelkeys seeds.
	 * S in RFC8931, SK_1 and S in XMSS-T paper.
	 */
	otsSeed []byte
	/* n-byte pubSeed is used to randomize the hash to generate WOTS verification keys.
	 * SEED in RFC8931, SEED in XMSS-T paper.
	 */
	pubSeed []byte
	/* n-byte msgSeed is used to randomize the message hash when signing.
	 * SK_PRF in RFC8931, SK_2 in XMSS-T paper.
	 */
	msgSeed []byte
	// n-byte root node of the root tree.
	root []byte
	// Context containing the MBPQS parameters.
	ctx *Context
}

// PublicKey is a MBPQS public key.
type PublicKey struct {
	// Height of the root tree.
	height byte
	// n-byte root node of the root tree.
	root []byte
	/* n-byte pubSeed used to randomize the hash to generate WOTS verification keys.
	 * SEED in RFC8931, SEED in XMSS-T paper
	 */
	pubSeed []byte
}

func setParam(n, w, H, h, d uint32) *Params {
	return &Params{
		n: n,
		w: w,
		H: H,
		h: h,
		d: d,
	}
}

func GenerateKeyPair(p Params) (*PrivateKey, *PublicKey, error) {
	ctx, err := newContext(p)
	if err != nil {
		return nil, nil, err
	}
	otsS, err := randomBytes(ctx.params.n)
	if err != nil {
		return nil, nil, err
	}
	pubS, err := randomBytes(ctx.params.n)
	if err != nil {
		return nil, nil, err
	}
	msgS, err := randomBytes(ctx.params.n)
	if err != nil {
		return nil, nil, err
	}
	return ctx.DeriveKeyPair(otsS, pubS, msgS)
}
