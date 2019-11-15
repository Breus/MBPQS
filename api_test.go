// Black box testing, that's why we have mbpqs_test as package instead of mbpqs.
// This way, we know that accessibility of the api functions alone provides enough to fully function.
package mbpqs_test

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/Breus/mbpqs"
)

// This test adds and verifies multiple channels,
// consequently signs and verifies multiple messages in each channel,
// grows the channel and signs/verifies new messages.
func TestMultiChannels(t *testing.T) {
	// Generate parameterized keypair.
	var rootH uint32 = 2
	var chanH uint32 = 10
	var c uint16 = 0
	var w uint16 = 4
	var n uint32 = 32
	sk, pk, err := mbpqs.GenKeyPair(n, rootH, chanH, c, w)
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

		// Set the authnode to the root of the first blocks tree.
		authNode := rtSig.GetSignedRoot()

		// Now, we sign 2^chanH times, and verify the signatures in each channel.
		for j := 0; j < int(chanH)-1; j++ {
			msg := []byte("Message" + string(j))
			sig, err := sk.SignChannelMsg(chIdx, msg)
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
			authNode = sig.NextAuthNode()
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

		authNode = gs.NextAuthNode()
		// We have new keys to sign, lets use them!
		for h := 0; h < int(chanH-1); h++ {
			msg := []byte("Message after growth" + string(h))
			sig, err := sk.SignChannelMsg(chIdx, msg)
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
			authNode = sig.NextAuthNode()
		}
	}
}

// Multichain mimick for testing purposes.
type Multichain struct {
	channels []Blockchain
}

// Blockchain mimick for testing purposes.
type Blockchain struct {
	blocks []mbpqs.Signature
}

// TestSignStoreVerify signs multiple messages in multiple channels.
// Subsequently, the signatures are stored on the 'blockchain'.
// Then, we test if a verifier can indeed verify the signatures in the
// channel it has access to.
func TestSignStoreVerify(t *testing.T) {
	var nrChains int = 1
	// Make a multichain with 'nrChains' blockchains.
	mc := Multichain{
		channels: make([]Blockchain, nrChains),
	}

	// Generate parameterized keypair.
	var rootH uint32 = 2
	var chanH uint32 = 4
	var c uint16 = 1
	var w uint16 = 4
	var n uint32 = 32
	sk, pk, err := mbpqs.GenKeyPair(n, rootH, chanH, c, w)
	if err != nil {
		t.Fatalf("KeyGen failed: %s\n", err)
	}

	// SIGN + STORE ON "BLOCKCHAIN"
	// Add to each channel a keychannel.
	for i := 0; i < nrChains; i++ {
		chIdx, rtSig, err := sk.AddChannel()
		if err != nil {
			t.Fatalf("Addition of channel %d failed with error %s\n", chIdx, err)
		}

		// Add the rootSig to the blocks.
		mc.channels[i].blocks = append(mc.channels[i].blocks, rtSig)

		// Lets sign 10 messages in each channel and add it to its respective blocks.
		for j := 0; j < int(chanH-1); j++ {
			msg := []byte("Message in channel" + string(chIdx))
			msgSig, err := sk.SignMsg(chIdx, msg)
			if err != nil {
				t.Fatalf("Signing message %d in channel %d failed with error %s\n", j, chIdx, err)
			}
			mc.channels[i].blocks = append(mc.channels[i].blocks, msgSig)
		}
		// Lets also test a growsignature.
		growSig, err := sk.GrowChannel(chIdx)
		if err != nil {
			t.Fatalf("Growing channel %d failed with error %s\n", chIdx, err)
		}
		mc.channels[i].blocks = append(mc.channels[i].blocks, growSig)

		// Lets add a few more message siganture to test.
		for k := 0; k < int(chanH-1); k++ {
			msg := []byte("Message in channel" + string(chIdx))
			msgSig, err := sk.SignMsg(chIdx, msg)
			if err != nil {
				t.Fatalf("Signing message %d in channel %d failed with error %s\n", k, chIdx, err)
			}
			mc.channels[i].blocks = append(mc.channels[i].blocks, msgSig)
		}
	}

	// VERIFY FROM "BLOCKCHAIN"
	// Verify the rootSignature for each channel.
	for i := 0; i < nrChains; i++ {
		// Counter to count correct signature verifications for this channel.
		var counter int

		// Retrieve the current channel in the multichain
		curChan := mc.channels[i]

		var nextAuthNode []byte

		// Lets verify the signatures in the channel.
		for j := 0; j < int(len(curChan.blocks)); j++ {
			// Current Signature block
			curSig := curChan.blocks[j]
			curMsg := []byte("Message in channel" + string(i))
			acceptMsg, err := pk.Verify(curSig, curMsg, nextAuthNode)
			if err != nil {
				t.Fatalf("Message verification in channel %d failed with error %s", i+1, err)
			}
			if !acceptMsg {
				t.Fatalf("Verification of correct message %d on chain %d not accepted", j, i)
			} else {
				counter++
			}
			nextAuthNode = curSig.NextAuthNode(nextAuthNode)
		}
		if counter != len(curChan.blocks) {
			t.Fatal("Not enough signatures are correctly verified")
		}
		if counter != int(2*(chanH-1)+2) {
			t.Fatal("Not enough signatures verified correctly")
		}
	}

}

func TestVerifyMsg(t *testing.T) {
	sigs := 1000
	for H := 1; H < 2; H++ {
		p := mbpqs.InitParam(32, uint32(H), 1001, 1, 4)
		sk, pk, err := mbpqs.GenerateKeyPair(p, 0)
		if err != nil {
			t.Fatal("Generating key pair failed with error: ", err)
		}
		chIdx, RtSig, err := sk.AddChannel()
		if err != nil {
			t.Fatal("Adding channel failed with error: ", err)
		}
		msg := make([]byte, 512000)
		var sigChain []mbpqs.Signature
		authNode := RtSig.NextAuthNode()
		for j := 0; j < sigs; j++ {

			rand.Seed(int64(j))
			rand.Read(msg)
			sig, err := sk.SignMsg(chIdx, msg)
			if err != nil {
				t.Fatal("message signing failed with error:", err)
			}
			sigChain = append(sigChain, sig)

			accept, err := pk.VerifyMsg(sigChain[j].(*mbpqs.MsgSignature), msg, authNode)

			if err != nil {
				t.Fatal("Message verification failed with error:", err)
			}
			if !accept {
				t.Fatal("Correct signature not verified")
			}
			authNode = sigChain[j].NextAuthNode(authNode)

		}
	}
}
