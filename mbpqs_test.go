package mbpqs

import (
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	params := &Params{n: 32, w: 16, ge: 1, rootH: 2, chanH: 6}
	sk, pk, err := GenerateKeyPair(params)
	if err != nil {
		t.Fatalf("key generation went wrong %s", err)
	}

	// Check if we can sign and verify 2^rootH times.
	for i := 0; i < 1<<params.rootH-1; i++ {
		msg := []byte("Hello message" + string(i))
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
	params = &Params{n: 64, w: 4, ge: 1, rootH: 12, chanH: 3}
	sk, pk, err = GenerateKeyPair(params)
	if err != nil {
		t.Fatalf("key generation went wrong %s", err)
	}

	msg1 := []byte("Yes")
	msg2 := []byte("Yes.")

	sign, _ = sk.SignChannelRoot(msg1)
	accept, _ := pk.VerifyChannelRoot(sign, msg2)
	if accept {
		t.Fatal("Can verify the signature over a different message!")
	}
}

func TestNonExistingChannelSigning(t *testing.T) {
	sk, _, err := GenerateKeyPair(&Params{n: 32, w: 4, ge: 1, rootH: 4, chanH: 10})
	if err != nil {
		t.Fatalf("keygeneration gave error %s", err)
	}
	_, err = sk.SignChannelMsg(0, []byte("Hello!"))
	if err == nil {
		t.Fatal("signing in a non-existant channel did not give an error")
	}
}

func TestChannelSigning(t *testing.T) {
	// Create MBPQS keypair.
	sk, pk, err := GenerateKeyPair(&Params{n: 32, w: 4, ge: 1, rootH: 3, chanH: 4})
	if err != nil {
		t.Fatalf("keygeneration gave error %s", err)
	}

	// Create a channel.
	chIdx, chRtSig, err := sk.createChannel()
	if err != nil {
		t.Fatalf("channel creation failed with error %s", err)
	}

	// Sign the message "hello" in this channel.
	msg := []byte("This is the message to be signed")
	chSig, err := sk.SignChannelMsg(chIdx, msg)
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

	// Sign the message "hello" in this channel.
	msg3 := []byte("This is the message to be signed")
	chSig2, err := sk.SignChannelMsg(chIdx, msg3)
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

	// Sign the message "hello" in this channel.
	msg4 := []byte("This is the message to be signed")
	chSig3, err := sk.SignChannelMsg(chIdx, msg4)
	if err != nil {
		t.Fatalf("signing in channel failed with error %s", err)
	}

	accept3, err := pk.VerifyChannelMsg(chSig3, msg4, chSig2.authPath)
	if err != nil {
		t.Fatalf("verification of right message failed with errror %s", err)
	}
	if !accept3 {
		t.Fatalf("verification of correct message/signature pair not accepted")
	}
}
