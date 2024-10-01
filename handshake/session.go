package handshake

// One way of generating random numbers:
// LCG linear congruential generator - x_(n+1) = (aX_(n) +C) mod m
// tiny numbers are type of iterative operation, result of current operation is variable in next operation
// Efficiency is based of a,c number you choose, to be 100% efficient u can chose a,c =1 and seed= 0, but it's simply is incremental way :)

// To choose good variable you can follow:
// c must be comprime with m gcd(c,m) =1
// a-1 must be divisible by all prime factor of m
// if m is a power of 2 a-1 must be divisible by 4
// If you need better efficient you can read: https://www.ams.org/journals/mcom/1999-68-225/S0025-5718-99-00996-5/S0025-5718-99-00996-5.pdf

type LCG8Bit struct {
	seed uint8
}

type LCG5Bit struct {
	seed uint8
}

func (lcg *LCG8Bit) Next() uint8 {
	const (
		modulus = uint8(255)
		a       = uint8(13)
		c       = uint8(17)
	)

	lcg.seed = (a*lcg.seed + c) % modulus

	return lcg.seed
}

func (lcg *LCG5Bit) Next() uint8 {
	const (
		modulus = uint8(32)
		a       = uint8(13)
		c       = uint8(17)
	)

	lcg.seed = (a*lcg.seed + c) % modulus

	return lcg.seed
}

var lcg8Bit = LCG8Bit{seed: 1}
var lcg5Bit = LCG5Bit{seed: 1}

func GenerateSession() []byte {
	num := make([]byte, lcg5Bit.Next())

	for i := range num {
		num[i] = lcg8Bit.Next()
	}

	return num
}
