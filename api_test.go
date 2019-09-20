// Black box testing, that's why we have mbpqs_test as package instead of mbpqs.
package mbpqs_test

import (
	"fmt"
	"testing"

	"github.com/Breus/mbpqs"
)

func TestSignAndVerifyMultipleChannels(t *testing.T) {
	var rootH uint32 = 6
	sk, pk, err := mbpqs.GenKeyPair(32, rootH, 120, 30, 4)
	if err != nil {
		t.Fatalf("KeyGen failed: %s\n", err)
	}

	for i := 0; i < (1 << 6); i++ {
		chIdx, rtSig, err := sk.AddChannel()
		if err != nil {
			t.Fatalf("Adding %d-th channel gone wrong", i)
		}
		fmt.Printf("Created channel %d\n", chIdx)

		accept, err := pk.VerifyChannel(rtSig)
		if err != nil {
			t.Fatalf("Channel verification failed: %s\n", err)
		}
		if !accept {
			t.Fatal("Channel verification not accepted")
		}
		sig, err := sk.SignChannelMsg(uint32(i+1), []byte("Hello"), false)
		if err != nil {
			t.Fatal("Message signing in channe; %i failed", i)
		}
	}

}
