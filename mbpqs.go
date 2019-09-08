package mbpqs

/* PrivateKey is a MBPQS private key */
type PrivateKey struct {
	/* 4-byte rootIndex holds the index of the next available ChannelKey in the root tree. */
	rootIdx uint32
	/* n-byte wotsSeed is used to pseudorandomly generate wots channelkeys seeds.
	 * S in RFC8931, SK_1 and S in XMSS-T paper.
	 */
	wotsSeed []byte
	/* n-byte pubSeed is used to randomize the hash to generate WOTS verificaiton keys.
	 * SEED in RFC8931, SEED in XMSS-T paper.
	 */
	pubSeed []byte
	/* n-byte msgSeed is used to randomize the message hash when signing.
	 * SK_PRF in RFC8931, SK_2 in XMSS-T paper.
	 */
	msgSeed []byte
	/* n-byte root node of the root tree */
	root []byte
}
