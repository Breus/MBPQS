package mbpqs

// SignatureSeqNo is the sequence number (index) of signatures and wotsKeys in channels and the root tree.
type SignatureSeqNo uint32

// Signature is the interface type for RootSignature, MsgSignature, and GrowSignature.
type Signature interface {
	NextAuthNode(prevAuthNode ...[]byte) []byte // Retrieve the current Authentication root after this signature is verified.
}

// RootSignature holds a signature on a channel by a rootTree leaf.
type RootSignature struct {
	ctx      *Context       // Defines the MBPQS instance which was used to create the Signature.
	seqNo    SignatureSeqNo // Index of the used leaf in the roottree used for signing.
	wotsSig  []byte         // The WOTS signature over the channel root.
	authPath []byte         // The authentication path for this signature to the rootTree root node.
	rootHash []byte         // ChannelRoot which is signed.
}

// GrowSignature is a signature of the last OTS key in a chain tree over the next chain tree root node.
type GrowSignature struct {
	ctx        *Context
	wotsSig    []byte
	rootHash   []byte
	chainSeqNo uint32
	chIdx      uint32
	layer      uint32
}

// MsgSignature holds a signature on a message in a channel.
type MsgSignature struct {
	ctx        *Context       // Context defines the mbpqs instance which was used to create the signature.
	seqNo      SignatureSeqNo // Sequence number of this signature in the channel.
	drv        []byte         // Digest randomized value (r).
	wotsSig    []byte         // The WOTS signature over the channel message.
	authPath   []byte         // Autpath to the rootSignature.
	chainSeqNo uint32         // Sequence number of this signature in the used chain tree.
	chIdx      uint32         // In which channel the signature.
	layer      uint32         // From which chainTree layer the key comes.
}

// GetSignedRoot returns the root hash field from the the RootSignature.
// This is the channel root signed by this signature.
func (rtSig *RootSignature) GetSignedRoot() []byte {
	return rtSig.rootHash
}

// NextAuthNode returns the authentication path for the RootSignature.
func (rtSig *RootSignature) NextAuthNode(prevAuthNode ...[]byte) []byte {
	return rtSig.GetSignedRoot()
}

// NextAuthNode returns the growSig root hash field from the GrowSignature.
// This is the chainTree root signed in this signature.
func (gs *GrowSignature) NextAuthNode(prevAuthNode ...[]byte) []byte {
	return gs.rootHash
}

// NextAuthNode returns the authentication node for the next signature from
// the current MsgSignature.
func (ms MsgSignature) NextAuthNode(prevAuthNode ...[]byte) []byte {
	if ms.lastMsgInChain() {
		return prevAuthNode[0]
	}
	return ms.authPath
}

// Return whether the msgsignature is the last one for the current chainTree.
func (ms *MsgSignature) lastMsgInChain() bool {
	if ms.chainSeqNo == (ms.ctx.chainTreeHeight(ms.layer) - 1) {
		return true
	}
	return false
}
