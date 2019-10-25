package mbpqs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"reflect"
	"testing"
)

func testWotsGenChain(ctx *Context, expect string, t *testing.T) {
	pubSeed := make([]byte, ctx.params.n)
	in := make([]byte, ctx.params.n)
	var addr [8]uint32
	for i := 0; i < int(ctx.params.n); i++ {
		pubSeed[i] = byte(2 * i)
		in[i] = byte(i)
	}
	for i := 0; i < 8; i++ {
		addr[i] = 500000000 * uint32(i)
	}
	ret := make([]byte, ctx.params.n)
	ctx.wotsGenChainInto(ctx.newScratchPad(), in, 4, 5,
		ctx.precomputeHashes(pubSeed, nil), address(addr), ret)
	val := hex.EncodeToString(ret)
	if val != expect {
		t.Errorf("wotsGenChain returned %s instead of %s", val, expect)
	}
}

func TestWotsGenChain(t *testing.T) {
	testWotsGenChain(NewContextFromOid(1), "2dd7fcc039afb02d35c4b370172a7714b909d74a6ef2463538e87b05ab573d18", t)
	testWotsGenChain(NewContextFromOid(4), "9b4cda48d43e57bf4b5eb57c7bd86126d523517f9f27dbe287c8501d3c00f4f1e37fab649ac4bec337bc92623acc837af3ac5be17ed1624a335eb02d0771a68c", t)
}

func testWotsPkGen(ctx *Context, expect string, t *testing.T) {
	pubSeed := make([]byte, ctx.params.n)
	skSeed := make([]byte, ctx.params.n)
	var addr [8]uint32
	for i := 0; i < int(ctx.params.n); i++ {
		pubSeed[i] = byte(2 * i)
		skSeed[i] = byte(i)
	}
	for i := 0; i < 8; i++ {
		addr[i] = 500000000 * uint32(i)
	}

	valHash := sha256.Sum256(
		ctx.wotsPkGen(ctx.newScratchPad(),
			ctx.precomputeHashes(pubSeed, skSeed), address(addr)))
	valHashPref := hex.EncodeToString(valHash[:8])
	if valHashPref != expect {
		t.Errorf("hash of wotsPkGen return value starts with %s instead of %s", valHashPref, expect)
	}
}

func TestWotsPkGen(t *testing.T) {
	testWotsPkGen(NewContextFromOid(2), "6a796e5e8c68a83d", t)
	testWotsPkGen(NewContextFromOid(4), "16d2cc6a8313c1ce", t)
}

func testWotsSign(ctx *Context, expect string, t *testing.T) {
	pubSeed := make([]byte, ctx.params.n)
	skSeed := make([]byte, ctx.params.n)
	msg := make([]byte, ctx.params.n)
	var addr [8]uint32
	for i := 0; i < int(ctx.params.n); i++ {
		pubSeed[i] = byte(2 * i)
		skSeed[i] = byte(i)
		msg[i] = byte(3 * i)
	}
	for i := 0; i < 8; i++ {
		addr[i] = 500000000 * uint32(i)
	}
	valHash := sha256.Sum256(
		ctx.wotsSign(ctx.newScratchPad(), msg, pubSeed, skSeed, address(addr)))
	valHashPref := hex.EncodeToString(valHash[:8])
	if valHashPref != expect {
		t.Errorf("hash of wotsSign return value starts with %s instead of %s", valHashPref, expect)
	}
}
func TestWotsSign(t *testing.T) {
	testWotsSign(NewContextFromOid(1), "81aae34c799751d3", t)
	testWotsSign(NewContextFromOid(4), "f3506bcdddda4a6b", t)
}

func testWotSignThenVerify(ctx *Context, t *testing.T) {
	pubSeed := make([]byte, ctx.params.n)
	skSeed := make([]byte, ctx.params.n)
	msg := make([]byte, ctx.params.n)
	var addr [8]uint32
	for i := 0; i < int(ctx.params.n); i++ {
		pubSeed[i] = byte(2 * i)
		skSeed[i] = byte(i)
		msg[i] = byte(3 * i)

		for i := 0; i < 8; i++ {
			addr[i] = 500000000 * uint32(i)
		}
		sig := ctx.wotsSign(ctx.newScratchPad(), msg, pubSeed, skSeed, address(addr))
		pk1 := ctx.wotsPkFromSig(ctx.newScratchPad(), sig, msg,
			ctx.precomputeHashes(pubSeed, nil), address(addr))
		pk2 := ctx.wotsPkGen(ctx.newScratchPad(),
			ctx.precomputeHashes(pubSeed, skSeed), address(addr))
		if !bytes.Equal(pk1, pk2) {
			t.Errorf("verification of signature failed")
		}
	}
}

func TestWotsSignThenVerify(t *testing.T) {
	testWotSignThenVerify(NewContextFromOid(1), t)
	testWotSignThenVerify(NewContextFromOid(4), t)
}

func BenchmarkWotsSign_SHA256_10(b *testing.B) {
	benchmarkWotsSign(b, 1)
}

func benchmarkWotsSign(b *testing.B, oid uint32) {
	ctx := NewContextFromOid(1)
	var pubSeed []byte = make([]byte, ctx.params.n)
	var skSeed []byte = make([]byte, ctx.params.n)
	var msg []byte = make([]byte, ctx.params.n)
	var addr [8]uint32
	for i := 0; i < int(ctx.params.n); i++ {
		pubSeed[i] = byte(2 * i)
		skSeed[i] = byte(i)
		msg[i] = byte(3 * i)
	}
	for i := 0; i < 8; i++ {
		addr[i] = 500000000 * uint32(i)
	}
	pad := ctx.newScratchPad()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		rand.Read(msg)
		ctx.wotsSign(pad, msg, pubSeed, skSeed, address(addr))
	}
}

func BenchmarkWotsVerify_SHA256(b *testing.B) {
	benchmarkWotsVerify(b, 1)
}

func benchmarkWotsVerify(b *testing.B, oid uint32) {
	ctx := NewContextFromOid(1)
	var pubSeed []byte = make([]byte, ctx.params.n)
	var skSeed []byte = make([]byte, ctx.params.n)
	var msg []byte = make([]byte, ctx.params.n)
	var addr [8]uint32
	for i := 0; i < int(ctx.params.n); i++ {
		pubSeed[i] = byte(2 * i)
		skSeed[i] = byte(i)
	}
	for i := 0; i < 8; i++ {
		addr[i] = 500000000 * uint32(i)
	}
	pad := ctx.newScratchPad()
	sig := ctx.wotsSign(pad, msg, pubSeed, skSeed, address(addr))
	ph := ctx.precomputeHashes(pubSeed, nil)
	rand.Read(msg)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {

		ctx.wotsPkFromSigInto(pad, sig, msg, ph, address(addr), pad.wotsBuf())
	}
}

func benchmarkWotsGenSk(b *testing.B, oid uint32) {
	ctx := NewContextFromOid(oid)
	out := make([]byte, ctx.params.n*ctx.params.wotsLen())
	var pubSeed []byte = make([]byte, ctx.params.n)
	var skSeed []byte = make([]byte, ctx.params.n)
	rand.Read(pubSeed)
	rand.Read(skSeed)
	ph := ctx.precomputeHashes(pubSeed, skSeed)
	pad := ctx.newScratchPad()
	var otsAddr address
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ctx.genWotsSk(pad, ph, otsAddr, out)
	}
}

func BenchmarkWotsGenSk(b *testing.B) {
	benchmarkWotsGenSk(b, 1)
}

func benchmarkWotsGenPk(ctx *Context, b *testing.B) {
	var pubSeed []byte = make([]byte, ctx.params.n)
	var skSeed []byte = make([]byte, ctx.params.n)
	ph := ctx.precomputeHashes(pubSeed, skSeed)
	pad := ctx.newScratchPad()
	var otsAddr address
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ctx.wotsPkGen(pad, ph, otsAddr)
	}
}

func BenchmarkWotsGenPk(b *testing.B) {
	benchmarkWotsGenPk(NewContextFromOid(1), b)
}

func benchmarkCompression(ctx *Context, b *testing.B) {
	var addr address
	pad := ctx.newScratchPad()
	hashPrfSk := sha256.New()
	hashPrfSk.Write(encodeUint64(hashPaddingPRF, int(ctx.params.n)))
	hashValPrfSk := reflect.ValueOf(hashPrfSk).Elem()
	out := make([]byte, 32)
	pad.hashPad.hVal.Set(hashValPrfSk)
	addrBuf := pad.prfAddrBuf()
	addr.writeInto(addrBuf)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pad.hashPad.h.Write(addrBuf)
		pad.hashPad.h.Sum(out[:0])
	}
}

func BenchmarkCompression(b *testing.B) {
	benchmarkCompression(NewContextFromOid(1), b)
}

func benchmarkGenWotsSeed(ctx *Context, b *testing.B) {
	var addr address
	var pubSeed []byte = make([]byte, ctx.params.n)
	var skSeed []byte = make([]byte, ctx.params.n)
	pad := ctx.newScratchPad()
	rand.Read(pubSeed)
	rand.Read(skSeed)
	ph := ctx.precomputeHashes(pubSeed, skSeed)
	out := make([]byte, ctx.params.n)
	for i := 0; i < b.N; i++ {
		ph.prfAddrSkSeedInto(pad, addr, out)
	}
}

func BenchmarkGenWotsSeed(b *testing.B) {
	benchmarkGenWotsSeed(NewContextFromOid(1), b)
}
