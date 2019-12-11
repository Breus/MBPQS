package mbpqs

import (
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	params := &Params{n: 32, w: 16, c: 1, rootH: 2, chanH: 2}
	sk, pk, err := GenerateKeyPair(params, 0)
	if err != nil {
		t.Fatalf("key generation went wrong %s", err)
	}

	// Check if we can sign and verify 2^rootH times.
	for i := 0; i < 1<<params.rootH; i++ {
		// Root messages will always be n-byte large because they are root of chain trees (n-byte nodes).
		msg := make([]byte, 32)
		sign, err := sk.SignChannelRoot(msg)
		if err != nil {
			t.Fatalf("signing crashed with error %s", err)
		}
		accept, err := pk.VerifyChannelRoot(sign, msg)
		if err != nil {
			t.Fatalf("verification crashed with error %s", err)
		}
		if !accept {
			t.Fatalf("non-correct signature %d", i)
		}
	}
	// Check if we can't sign more than 2^rootH times.
	msg := []byte("This is one message too much!")
	sign, err := sk.SignChannelRoot(msg)
	if err == nil || sign != nil {
		t.Fatalf("signing too many messages is allowed!")
	}

	// Check if we can't verify a incorrect signature.
	params = &Params{n: 64, w: 4, c: 1, rootH: 5, chanH: 3}
	sk, pk, err = GenerateKeyPair(params, 0)
	if err != nil {
		t.Fatalf("key generation went wrong %s", err)
	}

	msg2 := make([]byte, 64)
	msg1 := make([]byte, 64)
	msg1[0] = byte('h')
	sign, _ = sk.SignChannelRoot(msg2)
	accept, err := pk.VerifyChannelRoot(sign, msg1)
	if err == nil {
		t.Fatal("Verifying wrong signature didn't return an error: ", err)
	}
	if accept {
		t.Fatal("Can verify the signature over a different message!")
	}
}

func TestNonExistingChannelSigning(t *testing.T) {
	sk, _, err := GenerateKeyPair(&Params{n: 32, w: 4, c: 0, rootH: 4, chanH: 10}, 0)
	if err != nil {
		t.Fatalf("keygeneration gave error %s", err)
	}
	_, err = sk.SignMsg(1, []byte("Hello!"))
	if err == nil {
		t.Fatal("signing in a non-existant channel did not give an error")
	}
}

func TestChannelSigningEnoughSigsInChain(t *testing.T) {
	// Create MBPQS keypair.
	sk, pk, err := GenerateKeyPair(&Params{n: 32, w: 16, c: 1, rootH: 3, chanH: 5}, 0)
	if err != nil {
		t.Fatalf("keygeneration gave error %s", err)
	}

	// Create a channel.
	chIdx, chRtSig, err := sk.createChannel()
	if err != nil {
		t.Fatalf("channel creation failed with error %s", err)
	}

	// Sign the message msg in this channel.
	msg := []byte("This is the message to be signed")
	chSig, err := sk.SignMsg(chIdx, msg)
	if err != nil {
		t.Fatalf("signing in channel failed with error %s", err)
	}

	// Verify the channel message.
	accept, err := pk.VerifyChannelMsg(chSig, msg, chRtSig.rootHash)
	if err != nil {
		t.Fatalf("verification of right message failed with errror %s", err)
	}
	if !accept {
		t.Fatalf("verification of correct message/signature pair not accepted")
	}

	// Sign the message msg3 in this channel.
	msg3 := []byte("This is the message to be signed")
	chSig2, err := sk.SignMsg(chIdx, msg3)
	if err != nil {
		t.Fatalf("signing in channel failed with error %s", err)
	}
	accept2, err := pk.VerifyChannelMsg(chSig2, msg3, chSig.authPath)
	if err != nil {
		t.Fatalf("verification of right message failed with errror %s", err)
	}
	if !accept2 {
		t.Fatalf("verification of correct message/signature pair not accepted")
	}

	// Sign the message msg4 in this channel.
	msg4 := []byte("This is the message to be signed")
	chSig3, err := sk.SignMsg(chIdx, msg4)
	if err != nil {
		t.Fatalf("signing in channel failed with error %s", err)
	}

	// Verify a correct msg/signature pair.
	accept3, err := pk.VerifyChannelMsg(chSig3, msg4, chSig2.authPath)
	if err != nil {
		t.Fatalf("verification of right message failed with errror %s", err)
	}
	if !accept3 {
		t.Fatalf("verification of correct message/signature pair not accepted")
	}
}

func TestChannelSigningGrowing(t *testing.T) {
	var chanH uint32 = 4
	// Creat MBPQS keypair with low amount of chanH.
	sk, pk, err := GenerateKeyPair(&Params{n: 32, w: 4, c: 1, rootH: 4, chanH: chanH}, 0)
	if err != nil {
		t.Fatalf("keygeneration gave error %s", err)
	}

	// Create a channel.
	chIdx, chRtSig, err := sk.createChannel()
	if err != nil {
		t.Fatalf("channel creation failed with error %s", err)
	}

	// Sign the message msg in this channel.
	msg := []byte("This is the message to be signed")
	chSig, err := sk.SignMsg(chIdx, msg)
	if err != nil {
		t.Fatalf("signing in channel failed with error %s", err)
	}

	// Verify the channel message.
	accept, err := pk.VerifyChannelMsg(chSig, msg, chRtSig.rootHash)
	if err != nil {
		t.Fatalf("verification of right message failed with errror %s", err)
	}
	if !accept {
		t.Fatalf("verification of correct message/signature pair not accepted")
	}

	// Sign the message msg3 in this channel.
	msg2 := []byte("This is the message to be signed")
	chSig2, err := sk.SignMsg(chIdx, msg2)
	if err != nil {
		t.Fatalf("signing in channel failed with error %s", err)
	}

	accept2, err := pk.VerifyChannelMsg(chSig2, msg2, chSig.authPath)
	if err != nil {
		t.Fatalf("verification of right message failed with errror %s", err)
	}
	if !accept2 {
		t.Fatalf("verification of correct message/signature pair not accepted")
	}

	// Sign the message msg4 in this channel.
	msg3 := []byte("This is the message to be signed")
	chSig3, err := sk.SignMsg(chIdx, msg3)
	if err != nil {
		t.Fatalf("signing in channel failed with error %s", err)
	}

	// Verify a correct msg/signature pair.
	accept3, err := pk.VerifyChannelMsg(chSig3, msg3, chSig2.authPath)
	if err != nil {
		t.Fatalf("verification of right message failed with errror %s", err)
	}
	if !accept3 {
		t.Fatalf("verification of correct message/signature pair not accepted")
	}

	// Grow the channel, add another chainTree.
	growSig, err := sk.GrowChannel(chIdx)
	if err != nil {
		t.Fatalf("GrowSig creation failed with error %s", err)
	}

	// Verify the growSignature.
	accept4, err := pk.verifyChainTreeRoot(growSig, chSig3.authPath)
	if err != nil {
		t.Fatalf("Verification of growth signature failed with error %s", err)
	}
	if !accept4 {
		t.Fatalf("The growth signature was not accepted.")
	}

	// Sign the next message in the channel.
	msg5 := []byte("This is the message to be signed")
	chSig5, err := sk.SignMsg(chIdx, msg5)
	if err != nil {
		t.Fatalf("signing in channel failed with error %s", err)
	}

	// Verify the channel in the message.
	accept5, err := pk.VerifyChannelMsg(chSig5, msg5, growSig.rootHash)
	if err != nil {
		t.Fatalf("verification of right message failed with errror %s", err)
	}

	if !accept5 {
		t.Fatalf("verification of correct message/signature pair not accepted")
	}
}

// Testing multiple channel creations and verifications.
func TestChannelCreation(t *testing.T) {
	var rootH uint32 = 5
	sk, pk, err := GenKeyPair(32, rootH, 6, 0, 256)
	if err != nil {
		t.Fatalf("KeyGen crashed with error: %s\n", err)
	}
	for i := 0; i < (1 << rootH); i++ {
		chIdx, rootSig, err := sk.AddChannel()
		if err != nil {
			t.Fatalf("Channel %d in loop %d creation failed with error: %s\n", chIdx, i, err)
		}
		accept, err := pk.VerifyChannelRoot(rootSig, rootSig.rootHash)
		if err != nil {
			t.Fatalf("Channel %d verification did fail with error %s\n", chIdx, err)
		}
		if !accept {
			t.Fatalf("Correct channelRoot sig did not verify for channel %d\n", chIdx)
		}
	}
}

//Signing growing and signing :-)
func TestSignGrowSign(t *testing.T) {
	var chanH uint32 = 6
	msg := []byte("Message to be signed.")
	var gf uint32 = 3
	p := InitParam(32, 3, chanH, gf, 0, 4)
	sk, _, _ := GenerateKeyPair(p, 0)
	chIdx, _, _ := sk.AddChannel()
	var l uint32 = 1
	for i := 0; i < int(10); i++ {
		if i%int(chanH+(l-1)*gf-1) == 0 && i != 0 {
			i = 0
			_, err := sk.GrowChannel(chIdx)
			if err != nil {
				t.Fatalf("Channel growth failed with error %s", err)
			}
		}
		_, err := sk.SignMsg(chIdx, msg)
		if err != nil {
			t.Fatal("TestSignTest failed with error:", err)
		}
		l = sk.Channels[chIdx].layers
	}
}
