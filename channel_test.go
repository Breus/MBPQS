package mbpqs

import (
	"fmt"
	"testing"
)

func TestSignFromTill(t *testing.T) {
	sk, _, err := GenKeyPair(32, 2, 3, 0, 16)
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
	fmt.Println("?")
}

func TestPartials(t *testing.T) {
	sk, _, _ := GenKeyPair(32, 2, 3, 0, 16)
	var from uint32 = 0
	var till uint32 = 1
	ct := newChainTree(till-from+1, sk.ctx.params.n)
	fmt.Println(ct, "Height:", len(ct.buf))
	fmt.Println("Ct.height =", ct.height)
	sk.genChainTreeInto(sk.ctx.newScratchPad(), 1, 1, from, till, ct)
	fmt.Println(ct)
	// ct := sk.genChainTreeFromTill(sk.ctx.newScratchPad(), 1, 1, 0, 1)

}
