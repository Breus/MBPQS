package mbpqs

import (
	"testing"
)

func TestSignTill(t *testing.T) {
	sk, _, err := GenKeyPair(32, 2, 2, 0, 16)
	if err != nil {
		t.Fatalf("KeyGen failed with error: %s", err)
	}
	chIdx, _, err := sk.AddChannel()
	if err != nil {
		t.Fatalf("Channel addition failed with error: %s", err)
	}
	_, err = sk.SignChannelMsg(chIdx, []byte("Hello"))
	if err != nil {
		t.Fatalf("Message signing failed with error %s", err)
	}
}

func TestPartials(t *testing.T) {
	sk, _, _ := GenKeyPair(32, 2, 4, 0, 16)
	var till uint32 = 3
	ct := newChainTree(till+1, sk.ctx.params.n)
	sk.genChainTreeInto(sk.ctx.newScratchPad(), 1, 1, till, ct)
	// ct := sk.genChainTreeFromTill(sk.ctx.newScratchPad(), 1, 1, 0, 1)

}
