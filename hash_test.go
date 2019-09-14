package mbpqs

import (
	"encoding/hex"
	"testing"
)

func testHashMessage(ctx *Context, expect string, t *testing.T) {
	msg := []byte("test message!")
	R := make([]byte, ctx.params.n)
	root := make([]byte, ctx.params.n)
	var idx uint64 = 123456789123456789
	for i := 0; i < int(ctx.params.n); i++ {
		R[i] = byte(2 * i)
		root[i] = byte(i)
	}
	hVal, err := ctx.hashMessage(ctx.newScratchPad(),
		msg, R, root, idx)
	if err != nil {
		t.Errorf("hashMessage: %v", err)
		return
	}
	val := hex.EncodeToString(hVal)
	if val != expect {
		t.Errorf("hashMessage is %s instead of %s", val, expect)
	}
}
func TestHashMessage(t *testing.T) {
	testHashMessage(NewContextFromOid(1), "153f0c190e9e929f680c61757f1a8e48c6f532d2fef936b4227d9c99aa05efdf", t)
	testHashMessage(NewContextFromOid(4), "231602b3934f501086caf489aaa191befaed2b10bbc211b0516a96f11c76481383600892e4da35f20ccb6c252e1cbfb00640303efb235101b8d541544f74dce4", t)
}

func testPrf(ctx *Context, expect string, t *testing.T) {
	var addr address
	key := make([]byte, ctx.params.n)
	for i := 0; i < 8; i++ {
		addr[i] = uint32(i)
	}
	for i := 0; i < int(ctx.params.n); i++ {
		key[i] = byte(i)
	}
	val := hex.EncodeToString(ctx.prfAddr(ctx.newScratchPad(), addr, key))
	if val != expect {
		t.Errorf("prf is %s instead of %s", val, expect)
	}
}

func TestPrf(t *testing.T) {
	testPrf(NewContextFromOid(1), "c2d06093b5c98d5a6274066c923e194f18e53eeaf533bca12b92b789eb6866f0", t)
	testPrf(NewContextFromOid(4), "15a9ffa22a35fdf1308f08d7bfff0b049b3e4e93bbc1252f56846c775ccb00e6476073f6b02f2aba9ea514d497f6a4e71799e32ef2dfbb1f83b189f16d2acfa8", t)
}

func testF(ctx *Context, expect string, t *testing.T) {
	var in []byte = make([]byte, ctx.params.n)
	var pubSeed []byte = make([]byte, ctx.params.n)
	var addr [8]uint32
	for i := 0; i < int(ctx.params.n); i++ {
		pubSeed[i] = byte(2 * i)
		in[i] = byte(i)
	}
	for i := 0; i < 8; i++ {
		addr[i] = 500000000 * uint32(i)
	}
	val := hex.EncodeToString(ctx.f(in, pubSeed, address(addr)))
	if val != expect {
		t.Errorf("%s f is %s instead of %s", ctx.Name(), val, expect)
	}
}

func TestF(t *testing.T) {
	testF(NewContextFromOid(1), "81d77ae441c1daa5eee9897a826266dc3cc03cf2d7e1393391467655965cd7e9", t)
	testF(NewContextFromOid(4), "4bc706c40b665a2e30ea47f1997a785c0e09295ae85687023e829b49f6ec95ea0cf5aaab320d4b8f0c215ce76acec674c7becade6d7eab4abd971cc3bed680aa", t)
}

func testH(ctx *Context, expect string, t *testing.T) {
	var left []byte = make([]byte, ctx.params.n)
	var right []byte = make([]byte, ctx.params.n)
	var pubSeed []byte = make([]byte, ctx.params.n)
	var addr [8]uint32
	for i := 0; i < int(ctx.params.n); i++ {
		pubSeed[i] = byte(2 * i)
		left[i] = byte(i)
		right[i] = byte(i + int(ctx.params.n))
	}
	for i := 0; i < 8; i++ {
		addr[i] = 500000000 * uint32(i)
	}
	val := hex.EncodeToString(ctx.h(left, right, pubSeed, address(addr)))
	if val != expect {
		t.Errorf("%s f is %s instead of %s", ctx.Name(), val, expect)
	}
}

func TestH(t *testing.T) {
	testH(NewContextFromOid(1), "6ed9fa805fc4aa2ee130be19801ce4a232b002ea709a915dbe0beddb11eca4e9", t)
	testH(NewContextFromOid(4), "cd341b0001f4adb53bedb31e3e54e4f4a2e520daf6d6bfeb1f2fbb5982f40adaa2c1e8b715b72644bf49b016404273ebf94ebe5b0d1911e9478ac94cd2aec537", t)
}
