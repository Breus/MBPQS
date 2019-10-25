package mbpqs

import (
	"encoding/hex"
	"math/rand"
	"testing"
)

func testLTree(ctx *Context, expect string, t *testing.T) {
	pk := make([]byte, ctx.params.n*ctx.wotsLen)
	pubSeed := make([]byte, ctx.params.n)
	var addr [8]uint32
	for i := 0; i < len(pk); i++ {
		pk[i] = byte(i)
	}
	for i := 0; i < int(ctx.params.n); i++ {
		pubSeed[i] = byte(2 * i)
	}
	for i := 0; i < 8; i++ {
		addr[i] = 500000000 * uint32(i)
	}
	val := hex.EncodeToString(ctx.lTree(ctx.newScratchPad(), pk,
		ctx.precomputeHashes(pubSeed, nil), address(addr)))
	if val != expect {
		t.Errorf("ltree returned %s instead of %s", val, expect)
	}
}

func TestLTree(t *testing.T) {
	testLTree(NewContextFromOid(1), "c6686977111a5ecd45156ddc0230d71a6149fc9d640619e617efa10f406367a9", t)
	testLTree(NewContextFromOid(4), "493a524b6dd6ba40f62942a54e1ddf25ea092fbbb533e2cd4d1320c990b4d23a190b33a01f4c71132d744f2bbd635380ef5a98521729b95c4ac5b227a0eabfce", t)
}

func testGetWotsSeed(ctx *Context, expect string, t *testing.T) {
	skSeed := make([]byte, ctx.params.n)
	var addr [8]uint32
	for i := 0; i < int(ctx.params.n); i++ {
		skSeed[i] = byte(i)
	}
	for i := 0; i < 8; i++ {
		addr[i] = 500000000 * uint32(i)
	}
	val := hex.EncodeToString(ctx.getWotsSeed(ctx.newScratchPad(),
		ctx.precomputeHashes(skSeed, skSeed), addr))
	if val != expect {
		t.Errorf("getWotsSeed returned %s instead of %s", val, expect)
	}
}

func TestGetWotsSeed(t *testing.T) {
	testGetWotsSeed(NewContextFromOid(1), "a5b6a82db4e6d116400eb532da8f95ea664bd732cb04f37de025061fe31b506a", t)
	testGetWotsSeed(NewContextFromOid(4), "f0c03883bfb127a613377f130b34d67057df7697fd568597ff466dababfb76c3537a218aed8408db068dfb118a7f0d9aac5ac05b6c4a7df5bb34fd0cc788c503", t)
}

func testGenLeaf(ctx *Context, expect string, t *testing.T) {
	skSeed := make([]byte, ctx.params.n)
	pubSeed := make([]byte, ctx.params.n)
	var lTreeAddr, otsAddr [8]uint32
	for i := 0; i < int(ctx.params.n); i++ {
		skSeed[i] = byte(i)
		pubSeed[i] = byte(2 * i)
	}
	for i := 0; i < 8; i++ {
		otsAddr[i] = 500000000 * uint32(i)
		lTreeAddr[i] = 400000000 * uint32(i)
	}
	val := hex.EncodeToString(ctx.genLeaf(ctx.newScratchPad(),
		ctx.precomputeHashes(pubSeed, skSeed), lTreeAddr, otsAddr))
	if val != expect {
		t.Errorf("genLeaf returned %s instead of %s", val, expect)
	}
}

func TestGenLeaf(t *testing.T) {
	testGenLeaf(NewContextFromOid(1), "ded138d113fe40973955ad072e901e98588c62ea0cc24e51060891fb1d8390f5", t)
	testGenLeaf(NewContextFromOid(4), "e022bc5c092d56020982bf32ae930bb0891fa8a0c9bd275061d0a3696b5773d0255ab47577447f8f80bb0f611e7efb9528e5d727611931eaaf0b05875d3b83d4", t)
}

func testGenRootTree(ctx *Context, expect string, t *testing.T) {
	skSeed := make([]byte, ctx.params.n)
	pubSeed := make([]byte, ctx.params.n)
	for i := 0; i < int(ctx.params.n); i++ {
		skSeed[i] = byte(i)
		pubSeed[i] = byte(2 * i)
	}
	rt := ctx.genRootTree(ctx.newScratchPad(), ctx.precomputeHashes(pubSeed, skSeed))
	val := hex.EncodeToString(rt.node(ctx.params.rootH, 0))
	if val != expect {
		t.Errorf("genRootTree generated root %s instead of %s", val, expect)
	}
}

func TestRootTree10(t *testing.T) {
	testGenRootTree(NewContextFromOid(0), "416bea4b44c0e5a52dc8bd65df2929579de7123cd01926972e58f1b22b1c63d7", t)
}

func TestRootTree16(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping genSubTree of 2^16")
	}
	testGenRootTree(NewContextFromOid(1), "f903f838e63e4d2851cd0bb7781f964f302dc88ee30a8944a288740420df23f2", t)
}

func TestRootTree(t *testing.T) {
	var th uint32 = 3
	var h, i uint32
	mt := newRootTree(th, 2)
	for h = 0; h < th; h++ {
		for i = 0; i < 1<<(th-h-1); i++ {
			mt.node(h, i)[0] = byte(h)
			mt.node(h, i)[1] = byte(i)
		}
	}
	for h = 0; h < th; h++ {
		for i = 0; i < 1<<(th-h-1); i++ {
			if mt.node(h, i)[0] != byte(h) ||
				mt.node(h, i)[1] != byte(i) {
				t.Errorf("Node (%d,%d) has wrong value", h, i)
			}
		}
	}
}

func benchmarkGenLeaf(ctx *Context, b *testing.B) {
	skSeed := make([]byte, ctx.params.n)
	pubSeed := make([]byte, ctx.params.n)
	var lTreeAddr, otsAddr address
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ctx.genLeaf(ctx.newScratchPad(), ctx.precomputeHashes(pubSeed, skSeed), lTreeAddr, otsAddr)
	}
}

func BenchmarkGenLeaf(b *testing.B) {
	benchmarkGenLeaf(NewContextFromOid(1), b)
}

func benchmarkLtree(ctx *Context, b *testing.B) {
	pad := ctx.newScratchPad()
	var pubSeed []byte = make([]byte, ctx.params.n)
	var skSeed []byte = make([]byte, ctx.params.n)
	ph := ctx.precomputeHashes(pubSeed, skSeed)
	var otsAddr, lTreeAddr address
	wotsPK := ctx.wotsPkGen(pad, ph, otsAddr)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.lTree(pad, wotsPK, ph, lTreeAddr)
	}
}

func BenchmarkLtree(b *testing.B) {
	benchmarkLtree(NewContextFromOid(1), b)
}

func BenchmarkInternalNode(b *testing.B) {
	benchmarkInternalNode(NewContextFromOid(1), b)
}

func benchmarkInternalNode(ctx *Context, b *testing.B) {
	pad := ctx.newScratchPad()
	var pubSeed []byte = make([]byte, ctx.params.n)
	var skSeed []byte = make([]byte, ctx.params.n)
	ph := ctx.precomputeHashes(pubSeed, skSeed)
	leftNode := make([]byte, 32)
	rightNode := make([]byte, 32)
	rand.Read(leftNode)
	rand.Read(rightNode)
	out := make([]byte, 32)
	var treeAddr address

	for i := 0; i < b.N; i++ {
		ctx.hInto(pad, leftNode, rightNode, ph, treeAddr, out)
	}
}
