// Black box testing, that's why we have mbpqs_test as package instead of mbpqs.
// This way, we know that accessibility of the api functions alone provides enough to fully function.
package mbpqs_test

import (
	"fmt"
	"testing"

	"github.com/Breus/mbpqs"
)

// This test adds and verifies multiple channels,
// consequently signs and verifies multiple messages in each channel,
// grows the channel and signs/verifies new messages.
func TestMultiChannels(t *testing.T) {
	// Generate parameterized keypair.
	var rootH uint32 = 3
	var chanH uint32 = 20
	var ge uint32 = 20
	var w uint16 = 4
	var n uint32 = 32
	sk, pk, err := mbpqs.GenKeyPair(n, rootH, chanH, ge, w)
	if err != nil {
		t.Fatalf("KeyGen failed: %s\n", err)
	}

	// Add 2^rootH channels for testing.
	for i := 0; i < (1 << rootH); i++ {
		chIdx, rtSig, err := sk.AddChannel()
		fmt.Printf("Added channel with ID: %d\n", chIdx)
		if err != nil {
			t.Fatalf("Adding %d-th channel failed with error %s\n", chIdx, err)
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

		// Now, we sign 2^chanH times, and verify the signatures in each channel.
		for j := 0; j < int(chanH)-1; j++ {
			msg := []byte("Message" + string(j))
			sig, err := sk.SignChannelMsg(chIdx, msg, false)
			if err != nil {
				t.Fatalf("Message signing in channel %d failed with error %s\n", chIdx, err)
			}
			fmt.Printf("Signed message %d in channel %d\n", j, chIdx)

			acceptSig, err := pk.VerifyMsg(sig, msg, authNode)
			if err != nil {
				t.Fatalf("Verification message %d in channel %d failed with error %s\n", j, i, err)
			}
			if !acceptSig {
				t.Fatalf("Verification of correct message/sig not accepted for message %d in channel %d\n", j, i)
			} else {
				fmt.Printf("Correctly verified message %d in channel %d\n", j, chIdx)
			}
			authNode = sig.GetAuthField()
		}
		// Let's grow the channels!
		gs, err := sk.GrowChannel(chIdx)
		if err != nil {
			t.Fatalf("Growing channel %d failed with error %s\n", chIdx, err)
		}
		// Let's verifiy the growth signature.
		acceptGrowth, err := pk.VerifyGrow(gs, authNode)
		if err != nil {
			t.Fatalf("Verification of growth channel %d failed with error: %s\n", chIdx, err)
		}
		if !acceptGrowth {
			t.Fatalf("Correct growth of channel %d not accepted", chIdx)
		}

		authNode = gs.GetRootField()
		// We have new keys to sign, lets use them!
		for h := 0; h < int(chanH+ge-1); h++ {
			msg := []byte("Message after growth" + string(h))
			sig, err := sk.SignChannelMsg(chIdx, msg, false)
			if err != nil {
				t.Fatalf("Message signing in channel %d failed with error %s\n", chIdx, err)
			}
			fmt.Printf("Signed message %d in channel %d\n", h, chIdx)

			acceptSig, err := pk.VerifyMsg(sig, msg, authNode)
			if err != nil {
				t.Fatalf("Verification message %d in channel %d failed with error %s\n", h, i, err)
			}
			if !acceptSig {
				t.Fatalf("Verification of correct message/sig not accepted for message %d in channel %d\n", h, i)
			} else {
				fmt.Printf("Correctly verified message %d in channel %d\n", h, chIdx)
			}
			authNode = sig.GetAuthField()
		}
	}
}

// TestSignStoreVerify signs multiple messages in multiple channels.
// Subsequently, the signatures are stored on the 'blockchain'.
// Then, we test if a verifier can indeed verify the signatures in the
// channel it has access to.
func TestSignStoreVerify(t *testing.T) {

}
