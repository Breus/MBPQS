package mbpqs

import (
	"log"
	"math/rand"
	"testing"
	"time"
)

// Benchmarks for Initial Key Generation.
func benchmarkKeyGen(n, rtH uint32, w uint16, b *testing.B) {
	p := InitParam(n, rtH, 1000, 1000, w)
	for i := 0; i < b.N; i++ {
		GenerateKeyPair(p, 1)
	}
}

func BenchmarkKeyGen_n32_w4_H10(b *testing.B) {
	benchmarkKeyGen(32, 10, 4, b)
}

func BenchmarkKeyGen_n32_w4_H14(b *testing.B) {
	benchmarkKeyGen(32, 14, 4, b)
}

func BenchmarkKeyGen_n32_w4_H16(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping keygen benchmark for H = 16, w = 4")
	}
	benchmarkKeyGen(32, 16, 4, b)
}

func BenchmarkKeyGen_n32_w4_H20(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping keygen benchmark for H = 20, w = 4")
	}
	benchmarkKeyGen(32, 20, 4, b)
}

func BenchmarkKeyGen_n32_w16_H10(b *testing.B) {
	benchmarkKeyGen(32, 10, 16, b)
}

func BenchmarkKeyGen_n32_w16_H14(b *testing.B) {
	benchmarkKeyGen(32, 14, 16, b)
}

func BenchmarkKeyGen_n32_w16_H16(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping keygen benchmark for H = 16, w = 16")
	}
	benchmarkKeyGen(32, 16, 16, b)
}

func BenchmarkKeyGen_n32_w16_H20(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping keygen benchmark for H = 20, w = 16")
	}
	benchmarkKeyGen(32, 20, 16, b)
}

func BenchmarkKeyGen_n32_w256_H10(b *testing.B) {
	benchmarkKeyGen(32, 10, 256, b)
}

func BenchmarkKeyGen_n32_w256_H14(b *testing.B) {
	benchmarkKeyGen(32, 14, 256, b)
}

func BenchmarkKeyGen_n32_w256_H16(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping keygen benchmark for H = 16, w = 256")
	}
	benchmarkKeyGen(32, 16, 256, b)
}

func BenchmarkKeyGen_n32_w256_H20(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping keygen benchmark for H = 20, w = 256")
	}
	benchmarkKeyGen(32, 20, 256, b)
}

// From here, benchmarks for AddChannel
func benchmarkAddChannel(h uint32, w uint16, b *testing.B) {
	p := InitParam(32, 5, h, 0, w)
	sk, _, _ := GenerateKeyPair(p, 4)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sk.AddChannel()
	}
}

// AddChannel for w=4
func BenchmarkAddChannel_h10_w4(b *testing.B) {
	benchmarkAddChannel(5, 4, b)
}
func BenchmarkAddChannel_h100_w4(b *testing.B) {
	benchmarkAddChannel(100, 4, b)
}

// AddChannel for w=4
func BenchmarkAddChannel_h1000_w4(b *testing.B) {
	benchmarkAddChannel(1000, 4, b)
}

func BenchmarkAddChannel_h10000_w4(b *testing.B) {
	benchmarkAddChannel(10000, 4, b)
}

func BenchmarkAddChannel_h100000_w4(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark addchannel h=10000, w=4")
	}
	benchmarkAddChannel(100000, 4, b)
}

func BenchmarkAddChannel_h1000000_w4(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark addchannel h=100000, w=4")
	}
	benchmarkAddChannel(1000000, 4, b)
}

// AddChannel for w=16
func BenchmarkAddChannel_h100_w16(b *testing.B) {
	benchmarkAddChannel(100, 16, b)
}
func BenchmarkAddChannel_h1000_w16(b *testing.B) {
	benchmarkAddChannel(1000, 16, b)
}

func BenchmarkAddChannel_h10000_w16(b *testing.B) {
	benchmarkAddChannel(10000, 16, b)
}

func BenchmarkAddChannel_h100000_w16(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark addchannel h=10000, w=16")
	}
	benchmarkAddChannel(100000, 16, b)
}

func BenchmarkAddChannel_h1000000_w16(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark addchannel h=100000, w=16")
	}
	benchmarkAddChannel(1000000, 16, b)
}

// AddChannel for w=256
func BenchmarkAddChannel_h100_w256(b *testing.B) {
	benchmarkAddChannel(100, 256, b)
}

func BenchmarkAddChannel_h1000_w256(b *testing.B) {
	benchmarkAddChannel(1000, 256, b)
}

func BenchmarkAddChannel_h10000_w256(b *testing.B) {
	benchmarkAddChannel(10000, 256, b)
}

func BenchmarkAddChannel_h100000_w256(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark addchannel h=10000, w=256")
	}
	benchmarkAddChannel(100000, 256, b)
}

func BenchmarkAddChannel_h1000000_w256(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark addchannel h=100000, w=256")
	}
	benchmarkAddChannel(1000000, 256, b)
}

// From here, benchmarks for signing
func randomUint32(min, max int32) int32 {
	rand.Seed(time.Now().Unix())
	return rand.Int31n(max-min) + min
}

func benchmarkSignMsg(h uint32, w uint16, b *testing.B) {

	p := InitParam(32, 2, h, 0, w)
	sk, _, err := GenerateKeyPair(p, 0)
	if err != nil {
		log.Fatal("BenchmarkSignMsg failed in keygen with error:", err)
	}
	chIdx, _, err := sk.AddChannel()
	if err != nil {
		log.Fatal("BenchmarkSignMsg failed with error:", err)
	}

	msg := make([]byte, 51200)
	rand.Read(msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = sk.SignChannelMsg(chIdx, msg)
	}
	b.StopTimer()
	if err != nil {
		log.Fatal("Signing failed in signmsg benchmark with error:", err)
	}
}

func BenchmarkSignMsg_h1_w4(b *testing.B) {
	benchmarkSignMsg(2, 4, b)
}

func BenchmarkSignMsg_h10_w4(b *testing.B) {
	benchmarkSignMsg(10, 4, b)
}

func BenchmarkSignMsg_h100_w4(b *testing.B) {
	benchmarkSignMsg(100, 4, b)
}

func BenchmarkSignMsg_h1000_w4(b *testing.B) {
	benchmarkSignMsg(1000, 4, b)
}

func BenchmarkSignMsg_h10000_w4(b *testing.B) {
	benchmarkSignMsg(10000, 4, b)
}
func BenchmarkSignMsg_h100000_w4(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping message signing benchmark with h = 100.000, w=4")
	}
	benchmarkSignMsg(100000, 4, b)
}

// SignMsg benchmark for w = 16
func BenchmarkSignMsg_h100_w16(b *testing.B) {
	benchmarkSignMsg(100, 16, b)
}

func BenchmarkSignMsg_h1000_w16(b *testing.B) {
	benchmarkSignMsg(1000, 16, b)
}

func BenchmarkSignMsg_h10000_w16(b *testing.B) {
	benchmarkSignMsg(10000, 16, b)
}
func BenchmarkSignMsg_h100000_w16(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping message signing benchmark with h = 100.000, w = 16")
	}
	benchmarkSignMsg(100000, 16, b)
}
