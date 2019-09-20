package mbpqs

// GenKeyPair generates a keypair for the given parameters.
func GenKeyPair(n, rtH, chanH, ge uint32, w uint16) (*PrivateKey, *PublicKey, error) {
	return GenerateKeyPair(InitParam(n, rtH, chanH, ge, w))
}

// AddChannel returns the ID of the added channel, and the signature of
// its initial chain tree root node.
func (sk *PrivateKey) AddChannel() (uint32, *RootSignature, error) {
	return sk.createChannel()
}

// VerifyChannel verifies that a channel is signed by a certain PublicKey.
func (pk *PublicKey) VerifyChannel(rt *RootSignature) (bool, error) {
	return pk.VerifyChannelRoot(rt, rt.rootHash)
}

// GrowChannel adds a chainTree to the channel.
func (sk *PrivateKey) GrowChannel(chIdx uint32) (*GrowSignature, error) {
	return sk.growChannel(chIdx)
}

// VerifyGrow verifies the growing signature.
func (pk *PublicKey) VerifyGrow(sig *GrowSignature, authNode []byte) (bool, error) {
	return pk.verifyChainTreeRoot(sig, authNode)
}

// SignMsg returns the signature over the message in channel with index chIdx.
func (sk *PrivateKey) SignMsg(chIdx uint32, msg []byte) (*MsgSignature, error) {
	return sk.SignChannelMsg(chIdx, msg, false)
}

// VerifyMsg returns if the signature/message pair verifies to the previous authNode.
func (pk *PublicKey) VerifyMsg(sig *MsgSignature, msg, authNode []byte) (
	bool, error) {
	return pk.VerifyChannelMsg(sig, msg, authNode)
}
