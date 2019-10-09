package mbpqs

import "fmt"

// GenKeyPair generates a keypair for the given parameters.
func GenKeyPair(n, rtH, chanH uint32, c uint16, w uint16) (*PrivateKey, *PublicKey, error) {
	return GenerateKeyPair(InitParam(n, rtH, chanH, c, w), 0)
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
	return sk.SignChannelMsg(chIdx, msg)
}

// VerifyMsg returns if the signature/message pair verifies to the previous authNode.
func (pk *PublicKey) VerifyMsg(sig *MsgSignature, msg, authNode []byte) (
	bool, error) {
	return pk.VerifyChannelMsg(sig, msg, authNode)
}

// Verify is the generic verification function for all signature types.
// First parameter: signature of any type
// Second (optional) parameter: message, plus additionally a authentication node as third.
// Authnod of growsignature and msgsignature should be CurAuthNode of previous signature.
func (pk *PublicKey) Verify(sig Signature, msgAuthNode ...[]byte) (bool, error) {
	switch t := sig.(type) {
	case *RootSignature:
		return pk.VerifyChannel(sig.(*RootSignature))
	case *MsgSignature:
		return pk.VerifyMsg(sig.(*MsgSignature), msgAuthNode[0], msgAuthNode[1])
	case *GrowSignature:
		return pk.VerifyGrow(sig.(*GrowSignature), msgAuthNode[1])
	default:
		return false, fmt.Errorf("unknown signature type %T", t)
	}
}

// The api functions to receive the next authentication node for signature
// chaining are located in signature.go.
