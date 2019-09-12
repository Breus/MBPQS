package mbpqs_test

import (
	"testing"

	"github.com/Breus/mbpqs"
)

func TestInitParam(t *testing.T) {
	param1 := mbpqs.InitParam(32, 6, 7, 2, 4)
	param2 := mbpqs.InitParam(32, 6, 7, 2, 16)
	param3 := mbpqs.InitParam(32, 6, 7, 2, 256)
	param4 := mbpqs.InitParam(64, 6, 7, 2, 4)
	param5 := mbpqs.InitParam(64, 6, 7, 2, 16)
	param6 := mbpqs.InitParam(64, 6, 7, 2, 256)

	sk, pk, err := mbpqs.GenerateKeyPair(param1)
	if err != nil {
		t.Error(err)
	}

}
