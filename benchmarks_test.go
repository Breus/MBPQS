package mbpqs

import (
	"fmt"
	"log"
	"math/rand"
	"testing"
	"time"
)

// Benchmark function for Initial Key Generation.
func benchmarkKeyGen(rtH uint32, w uint16, b *testing.B) {
	p := InitParam(32, rtH, 2, 0, 1, w)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GenerateKeyPair(p, 0)
	}
}

// Benchmark KeyGen for different parameters of w and H.
func BenchmarkKeyGen(b *testing.B) {
	wCases := []uint16{4, 16, 256}
	HCases := []uint32{2, 4, 6, 8, 10, 12, 16, 20}
	if testing.Short() {
		wCases = []uint16{4, 16}
		HCases = []uint32{2, 4, 6, 8, 10}
	}

	for _, w := range wCases {
		for _, H := range HCases {
			name := "w" + fmt.Sprint(w) + "-H" + fmt.Sprint(H)
			b.Run(name, func(b *testing.B) {
				benchmarkKeyGen(H, w, b)
			})
		}
	}

}

// Benchmark function for AddChannel.
func benchmarkAddChannel(h uint32, w uint16, b *testing.B) {
	p := InitParam(32, 2, h, 0, 1, w)
	sk, _, _ := GenerateKeyPair(p, 0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sk.AddChannel()
	}
}

// Run benchmark AddChannel for all combinations of w cases and h cases.
func BenchmarkAddChannel(b *testing.B) {
	wCases := []uint16{4, 16, 256}
	hCases := []uint32{2, 10, 100, 1000, 10000, 100000}
	if testing.Short() {
		wCases = []uint16{4, 16}
		hCases = []uint32{2, 10, 100, 1000}
	}
	for _, w := range wCases {
		for _, h := range hCases {
			name := "w" + fmt.Sprint(w) + "-h" + fmt.Sprint(h)
			b.Run(name, func(b *testing.B) {
				benchmarkAddChannel(h, w, b)
			})
		}
	}

}

// From here, benchmarks for signing
func randomUint32(min, max int32) int32 {
	rand.Seed(time.Now().Unix())
	return rand.Int31n(max-min) + min
}

func benchmarkSignMsg(h uint32, c, w uint16, b *testing.B) {

	p := InitParam(32, 2, h, 0, c, w)
	sk, _, err := GenerateKeyPair(p, 0)
	if err != nil {
		b.Fatal("BenchmarkSignMsg failed in keygen with error:", err)
	}
	chIdx, _, err := sk.AddChannel()
	if err != nil {
		b.Fatal("BenchmarkSignMsg failed with error:", err)
	}

	msg := make([]byte, 51200)
	rand.Read(msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		if i%int(h-1) == 0 && i > 0 {
			_, err := sk.GrowChannel(chIdx)
			if err != nil {
				log.Fatal("Growing channel failed with error:", err)
			}
			b.StartTimer()
		}
		b.StartTimer()
		_, err = sk.SignMsg(chIdx, msg)
		b.StopTimer()
	}

	if err != nil {
		log.Fatal("Signing failed in signmsg benchmark with error:", err)
	}
}

// Benchmark message signing for different values of c, w, and h.
func BenchmarkSignMsg(b *testing.B) {
	cCases := []uint16{0, 1}
	wCases := []uint16{4, 16, 256}
	hCases := []uint32{2, 10, 100, 1000, 10000}
	if testing.Short() {
		cCases = []uint16{1}
		wCases = []uint16{4, 16}
		hCases = []uint32{2, 10, 100, 1000, 10000}
	}

	for _, c := range cCases {
		for _, w := range wCases {
			for _, h := range hCases {
				name := "c" + fmt.Sprint(c) + "-w" + fmt.Sprint(w) + "-h" + fmt.Sprint(h)
				b.Run(name, func(b *testing.B) {
					benchmarkSignMsg(h, c, w, b)
				})
			}
		}
	}
}

func BenchmarkVerification(b *testing.B) {
	wCases := []uint16{4, 16}
	cCases := []uint16{0}
	for _, w := range wCases {
		for _, c := range cCases {
			name := "w" + fmt.Sprint(w) + "-Cache" + fmt.Sprint(c)
			b.Run(name, func(b *testing.B) {
				benchmarkVerification(w, c, b)
			})
		}

	}
}

func benchmarkVerification(w uint16, c uint16, b *testing.B) {
	p := InitParam(32, 2, 2, 0, c, w)

	sk, pk, err := GenerateKeyPair(p, 0)
	if err != nil {
		b.Fatal("Generating key pair failed with error: ", err)
	}
	chIdx, RtSig, err := sk.AddChannel()
	if err != nil {
		b.Fatal("Adding channel failed with error: ", err)
	}
	msg := make([]byte, 32)
	rand.Read(msg)
	var sigChain []Signature
	var msgChain [][]byte
	sig, err := sk.SignMsg(chIdx, msg)
	if err != nil {
		b.Fatal("Msg Sign failed with err", err)
	}
	sigChain = append(sigChain, sig)
	msgChain = append(msgChain, msg)

	_, err = sk.GrowChannel(chIdx)
	if err != nil {
		b.Fatalf("Channel growing failed with error %s", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		accept, err := pk.VerifyChannelRoot(RtSig, RtSig.NextAuthNode())
		//accept, err := pk.verifyChainTreeRoot(growSig, sig.NextAuthNode())
		//accept, err := pk.VerifyMsg(sig, msg, RtSig.NextAuthNode())
		if err != nil {
			b.Fatal("Signature verification failed with error:", err)
		}
		if !accept {
			b.Fatalf("Correct signature not verified correctly")
		}
	}

}

func benchmarkHashMessage(b *testing.B) {
	sk, _, err := GenKeyPair(32, 3, 4, 1, 16)
	if err != nil {
		b.Fatal("Benchmark HashMessage failed with error:", err)
	}
	msg := make([]byte, 51200)
	rand.Read(msg)
	pad := sk.ctx.newScratchPad()
	var sigIdx uint64 = 123021302101
	for i := 0; i < b.N; i++ {
		drv := sk.ctx.prfUint64(pad, sigIdx, sk.skPrf)
		sk.ctx.hashMessage(pad, msg, drv, sk.root, sigIdx)
	}

}

func BenchmarkHashMessage(b *testing.B) {
	benchmarkHashMessage(b)
}
