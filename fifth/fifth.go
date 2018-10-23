package fifth

import (
	"crypto/rand"
	"encoding/hex"
	_ "fmt"
	"math"
	"math/big"
)

func ExpInt64(a, b, p int64) int64 {
	c := new(big.Int).Exp(big.NewInt(a), big.NewInt(b), big.NewInt(p))
	return c.Int64()
}

func ExpInt(a, b, p *big.Int) *big.Int {
	c := new(big.Int).Exp(a, b, p)
	return c
}

func GenRandomInt64(num int64) int64 {
	res, _ := rand.Int(rand.Reader, big.NewInt(num))
	return res.Int64()
}

func GenRandomInt(num int64) *big.Int {
	res, _ := rand.Int(rand.Reader, big.NewInt(num))
	return res
}

func ToyDH() int64 {
	p := int64(37)
	g := int64(5)
	a := GenRandomInt64(math.MaxInt64) % p
	A := ExpInt64(g, a, p)
	b := GenRandomInt64(math.MaxInt64) % p
	B := ExpInt64(g, b, p)
	s1 := ExpInt64(B, a, p)
	s2 := ExpInt64(A, b, p)
	if s1 != s2 {
		panic("numbers are not equal")
	}
	return s1
}

func DH() *big.Int {
	pSlice, _ := hex.DecodeString(
		`ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff`)
	p := new(big.Int).SetBytes(pSlice)
	g := big.NewInt(2)
	a := GenRandomInt(math.MaxInt64)
	a.Mod(a, p)
	b := GenRandomInt(math.MaxInt64)
	b.Mod(b, p)
	A := ExpInt(g, a, p)
	B := ExpInt(g, b, p)
	s1 := ExpInt(B, a, p)
	s2 := ExpInt(A, b, p)
	if s1.Cmp(s2) != 0 {
		panic("numbers are not equal")
	}
	return s1
}
