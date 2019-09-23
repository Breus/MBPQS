// Black box testing, that's why we have mbpqs_test as package instead of mbpqs.
package mbpqs_test

import (
	"fmt"
	"testing"

	"github.com/Breus/mbpqs"
)

func TestMultiChannels(t *testing.T) {
	// Generate parameterized keypair.
	var rootH uint32 = 2
	var chanH uint32 = 10
	sk, pk, err := mbpqs.GenKeyPair(32, rootH, chanH, 30, 4)
	if err != nil {
		t.Fatalf("KeyGen failed: %s\n", err)
	}

	// Add 2^rootH channels for testing.
	for i := 0; i < (1 << rootH); i++ {
		chIdx, rtSig, err := sk.AddChannel()
		if err != nil {
			t.Fatalf("Adding %d-th channel gone wrong", i)
		}
		fmt.Printf("Created channel %d\n", chIdx)
		acceptChannel, err := pk.VerifyChannel(rtSig)
		if err != nil {
			t.Fatalf("Channel verification failed: %s\n", err)
		}
		if !acceptChannel {
			t.Fatal("Channel verification not accepted")
		}

		// Set the authnode to the root of the first chain tree.
		authNode := rtSig.GetRootField()
		fmt.Println(chanH)

		// Now, we sign 2^chanH times, and verify the signatures.
		for j := 0; j < int(chanH)-1; j++ {
			msg := []byte("Message" + string(j))
			sig, err := sk.SignChannelMsg(uint32(i+1), msg, false)
			if err != nil {
				t.Fatalf("Message signing in channel %d failed with error %s\n", i, err)
			}
			fmt.Printf("Signed message %d in channel %d\n", j, i)

			acceptSig, err := pk.VerifyMsg(sig, msg, authNode)
			if err != nil {
				t.Fatalf("Verification message %d in channel %d failed with error %s\n", j, i, err)
			}
			if !acceptSig {
				t.Fatalf("Verification of correct message/sig not accepted for message %d in channel %d\n", j, i)
			} else {
				fmt.Printf("Correctly verified message %d in channel %d\n", j, i)
			}
			authNode = sig.GetAuthField()
		}
	}

}
