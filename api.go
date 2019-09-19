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

// SignMsg returns the signature over the message in channel with index chIdx.
func (sk *PrivateKey) SignMsg(chIdx uint32, msg []byte) (*MsgSignature, error) {
	return sk.SignChannelMsg(chIdx, msg, false)
}

// VerifyMsg returns if the signature/message pair verifies to the previous authNode.
func (pk *PublicKey) VerifyMsg(sig *MsgSignature, msg, authNode []byte) (
	bool, error) {
	return pk.VerifyChannelMsg(sig, msg, authNode)
}
