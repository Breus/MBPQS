package mbpqs

import (
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	params := &Params{n: 32, w: 16, ge: 1, rootH: 2, chanH: 3}
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

func TestChannelSigning(t *testing.T) {
	sk, _, err := GenerateKeyPair(&Params{n: 32, w: 4, ge: 1, rootH: 4, chanH: 10})
	if err != nil {
		t.Fatalf("keygeneration gave error %s", err)
	}
	err = sk.SignChannelMsg(0, []byte("Hello!"))
	if err != nil {
		t.Fatalf("signChannelMsg failed with error %s", err)
	}
}
