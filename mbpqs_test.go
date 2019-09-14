package mbpqs

import (
	"fmt"
	"testing"
)

// func TestSigning(t *testing.T) {
// 	msg := []byte("Hello there!")
// 	params := &Params{n: 32, w: 16, d: 1, rootH: 5, chanH: 3}
// 	sk, _, err := GenerateKeyPair(params)
// 	if err != nil {
// 		t.Fatalf("key generation went wrong %s", err)
// 	}

// 	sign, err := sk.SignChannelRoot(msg)
// 	fmt.Printf("WotsSignature is length: %d", len(sign.wotsSig))
// 	if err != nil {
// 		t.Fatalf("signing crashed with error %s", err)
// 	}
// }

func TestSignThenVerify(t *testing.T) {
	msg := []byte("Hello there!")
	params := &Params{n: 32, w: 16, d: 1, rootH: 6, chanH: 3}
	sk, pk, err := GenerateKeyPair(params)
	if err != nil {
		t.Fatalf("key generation went wrong %s", err)
	}

	sign, err := sk.SignChannelRoot(msg)
	if err != nil {
		t.Fatalf("signing crashed with error %s", err)
	}
	fmt.Printf("Print sign lenght: %d", len(sign.authPath))
	accept, err := pk.VerifyChannelRoot(sign, msg)
	if err != nil {
		t.Fatalf("verification gave errror %s", err)
	}
	fmt.Println(accept)
}
