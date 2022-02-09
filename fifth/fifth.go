package fifth

import (
	"bytes"
	"crypto/rand"
	"knivets.com/cryptopals/fifth/srp"
	"knivets.com/cryptopals/second"
	"knivets.com/cryptopals/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
)

var DHp *big.Int
var DHg *big.Int
var alice string = "00:0a:95:9d:68:16"
var bob string = "00:0a:95:9d:68:17"
var eve string = "00:0a:95:9d:68:18"
var names map[string]string
var aliceState map[string]interface{}
var bobState map[string]interface{}
var eveState map[string]interface{}

func init() {
	DHpSlice, _ := hex.DecodeString(
		`ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff`)
	DHp = new(big.Int).SetBytes(DHpSlice)
	DHg = big.NewInt(2)
	aliceState = make(map[string]interface{})
	bobState = make(map[string]interface{})
	eveState = make(map[string]interface{})
	names = make(map[string]string)
	names[alice] = "alice"
	names[bob] = "bob"
	names[eve] = "eve"
}

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
	a := GenRandomInt(math.MaxInt64)
	a.Mod(a, DHp)
	b := GenRandomInt(math.MaxInt64)
	b.Mod(b, DHp)
	A := ExpInt(DHg, a, DHp)
	B := ExpInt(DHg, b, DHp)
	s1 := ExpInt(B, a, DHp)
	s2 := ExpInt(A, b, DHp)
	if s1.Cmp(s2) != 0 {
		panic("numbers are not equal")
	}
	return s1
}

func bytesToInt32(data []byte) int32 {
	var res int32
	buff := bytes.NewReader(data)
	_ = binary.Read(buff, binary.LittleEndian, &res)
	return res
}

func int32ToBytes(num int32) []byte {
	buff := new(bytes.Buffer)
	_ = binary.Write(buff, binary.LittleEndian, num)
	return buff.Bytes()
}

func parseMeta(payload []byte) (string, string, int) {
	if len(payload) <= 35 {
		panic("incorrect msg")
	}
	src := string(payload[0:17])
	dst := string(payload[17:34])
	op := int(payload[34:35][0])

	return src, dst, op
}

func produceMeta(src, dst string, op int) []byte {
	payload := []byte(src)
	payload = append(payload, []byte(dst)...)
	payload = append(payload, byte(op))

	return payload
}

func swtch(payload []byte) {
	_, dst, _ := parseMeta(payload)
	hosts := map[string]func([]byte){
		alice: Alice,
		bob:   Bob,
		eve:   Eve,
	}
	if host, ok := hosts[dst]; ok {
		host(payload)
	}
}

func encodeBigNums(data ...*big.Int) []byte {
	buff := [][]byte{}
	for _, item := range data {
		buff = append(buff, item.Bytes())
	}
	return encodeBytes(buff...)
}

func encodeBytes(data ...[]byte) []byte {
	res := []byte{}
	for _, item := range data {
		ln := int32ToBytes(int32(len(item)))
		res = append(res, ln...)
	}
	for _, item := range data {
		res = append(res, item...)
	}
	return res
}

func decodeByteSlices(data []byte, num int) [][]byte {
	res := [][]byte{}
	size := 4
	offset := int32(size * num)
	for i := 0; i < num; i++ {
		ln := bytesToInt32(data[i*size : (i+1)*size])
		res = append(res, data[offset:offset+ln])
		offset += ln
	}
	return res
}

func decodeBigNums(data []byte, num int) []*big.Int {
	res := []*big.Int{}
	bts := decodeByteSlices(data, num)
	for _, item := range bts {
		digit := new(big.Int).SetBytes(item)
		res = append(res, digit)
	}
	return res
}

func deriveKey(s *big.Int) []byte {
	dig := sha1.Sum(s.Bytes())
	return dig[0:16]
}

func BN(data interface{}) *big.Int {
	num, _ := data.(*big.Int)
	return num
}

func padAndEncryptCBC(msg []byte, s *big.Int) ([]byte, []byte) {
	key := deriveKey(s)
	msg = second.Pkcs7(msg, 16)
	iv := ExpInt(big.NewInt(7), GenRandomInt(math.MaxInt64), DHp).Bytes()[0:16]
	ct := second.EncryptCBC(msg, iv, key)
	return ct, iv
}

func decryptCBCAndStripPad(ct, iv []byte, s *big.Int) []byte {
	key := deriveKey(s)
	pt := second.DecryptCBC(ct, iv, key)
	pt, _ = second.StripPkcs7(pt)
	return pt
}

func genPrivKey(p *big.Int) *big.Int {
	a := GenRandomInt(math.MaxInt64)
	return a.Mod(a, p)
}

func wrapMsg(src, dst string, op int, payload []byte) []byte {
	res := produceMeta(src, dst, op)
	return append(res, payload...)
}

func msgTypeFirst(src, dst string, data []byte, state map[string]interface{}) []byte {
	p := DHp
	g := DHg
	a := genPrivKey(p)
	state["a"] = a
	state["p"] = p
	A := ExpInt(g, a, p)

	encoded := encodeBigNums(p, g, A)
	payload := wrapMsg(src, dst, 1, encoded)

	return payload
}

func msgTypeSecond(src, dst string, payload []byte, state map[string]interface{}) []byte {
	fmt.Printf("%s received op=1\n", names[dst])
	digits := decodeBigNums(payload, 3)
	p := digits[0]
	g := digits[1]
	A := digits[2]
	state["p"] = p
	state["g"] = g
	state["A"] = A

	b := genPrivKey(p)
	state["b"] = b
	B := ExpInt(g, b, p)

	encoded := encodeBigNums(B)
	reply := wrapMsg(dst, src, 2, encoded)

	return reply
}

func msgTypeThird(src, dst string, payload []byte, state map[string]interface{}) []byte {
	fmt.Printf("%s received op=2\n", names[dst])
	digits := decodeBigNums(payload, 1)
	B := digits[0]
	a := BN(state["a"])
	p := BN(state["p"])

	s := ExpInt(B, a, p)
	state["s"] = s
	msg := []byte("hello world")
	ct, iv := padAndEncryptCBC(msg, s)

	encoded := encodeBytes(ct, iv)
	reply := wrapMsg(dst, src, 3, encoded)

	return reply
}

func msgTypeFourth(src, dst string, payload []byte, state map[string]interface{}) []byte {
	fmt.Printf("%s received op=3\n", names[dst])
	b := BN(state["b"])
	p := BN(state["p"])
	A := BN(state["A"])
	decoded := decodeByteSlices(payload, 2)
	ct := decoded[0]
	iv := decoded[1]

	s := ExpInt(A, b, p)
	state["s"] = s
	pt := decryptCBCAndStripPad(ct, iv, s)
	// reencrypting
	ct, iv = padAndEncryptCBC(pt, s)

	encoded := encodeBytes(ct, iv)
	reply := wrapMsg(dst, src, 4, encoded)

	return reply
}

func msgTypeFifth(src, dst string, payload []byte, state map[string]interface{}) []byte {
	fmt.Printf("%s received op=4\n", names[dst])
	s := BN(state["s"])
	decoded := decodeByteSlices(payload, 2)
	ct := decoded[0]
	iv := decoded[1]

	pt := decryptCBCAndStripPad(ct, iv, s)
	fmt.Printf("%s received a message from %s: \"%v\"\n", names[dst], names[src], string(pt))

	return []byte{}
}

func msgTypeTenth(src, dst string, data []byte, state map[string]interface{}) []byte {
	p := DHp
	g := DHg
	state["p"] = p
	state["g"] = g

	encoded := encodeBigNums(p, g)
	payload := wrapMsg(src, dst, 10, encoded)

	return payload
}

func msgTypeEleventh(src, dst string, payload []byte, state map[string]interface{}) []byte {
	fmt.Printf("%s received op=10\n", names[dst])
	digits := decodeBigNums(payload, 2)
	p := digits[0]
	g := digits[1]
	state["p"] = p
	state["g"] = g

	encoded := encodeBytes([]byte{1})
	reply := wrapMsg(dst, src, 11, encoded)

	return reply
}

func msgTypeTwelfth(src, dst string, payload []byte, state map[string]interface{}) []byte {
	fmt.Printf("%s received op=11\n", names[dst])
	pl := decodeByteSlices(payload, 1)
	ack := pl[0][0]
	if ack != byte(1) {
		panic("p, g not ack")
	}
	p := BN(state["p"])
	g := BN(state["g"])

	a := genPrivKey(p)
	state["a"] = a
	A := ExpInt(g, a, p)

	encoded := encodeBigNums(A)
	reply := wrapMsg(dst, src, 12, encoded)

	return reply
}

func msgTypeThirteenth(src, dst string, payload []byte, state map[string]interface{}) []byte {
	fmt.Printf("%s received op=12\n", names[dst])
	digits := decodeBigNums(payload, 1)
	A := digits[0]
	state["A"] = A
	p := BN(state["p"])
	g := BN(state["g"])

	b := genPrivKey(p)
	state["b"] = b
	B := ExpInt(g, b, p)

	encoded := encodeBigNums(B)
	reply := wrapMsg(dst, src, 13, encoded)

	return reply
}

func msgTypeFourteenth(src, dst string, payload []byte, state map[string]interface{}) []byte {
	fmt.Printf("%s received op=13\n", names[dst])
	digits := decodeBigNums(payload, 1)
	B := digits[0]
	p := BN(state["p"])
	a := BN(state["a"])

	s := ExpInt(B, a, p)
	state["s"] = s
	msg := []byte("hello world")
	ct, iv := padAndEncryptCBC(msg, s)

	encoded := encodeBytes(ct, iv)
	reply := wrapMsg(dst, src, 14, encoded)

	return reply
}

func msgTypeFifteenth(src, dst string, payload []byte, state map[string]interface{}) []byte {
	fmt.Printf("%s received op=14\n", names[dst])
	b := BN(state["b"])
	p := BN(state["p"])
	A := BN(state["A"])
	decoded := decodeByteSlices(payload, 2)
	ct := decoded[0]
	iv := decoded[1]

	s := ExpInt(A, b, p)
	state["s"] = s
	pt := decryptCBCAndStripPad(ct, iv, s)
	ct, iv = padAndEncryptCBC(pt, s)

	encoded := encodeBytes(ct, iv)
	reply := wrapMsg(dst, src, 15, encoded)

	return reply
}

func msgTypeSixteenth(src, dst string, payload []byte, state map[string]interface{}) []byte {
	fmt.Printf("%s received op=15\n", names[dst])
	s := BN(state["s"])
	decoded := decodeByteSlices(payload, 2)
	ct := decoded[0]
	iv := decoded[1]

	pt := decryptCBCAndStripPad(ct, iv, s)
	fmt.Printf("%s received a message from %s: \"%v\"\n", names[dst], names[src], string(pt))

	return []byte{}
}

func Alice(payload []byte) {
	src, dst, op := parseMeta(payload)
	payload = payload[35:]
	state := aliceState
	if op > 0 && op < 10 {
		// 34 challenge protocol
		if op == 1 {
			reply := msgTypeSecond(src, dst, payload, state)
			swtch(reply)
		} else if op == 2 {
			reply := msgTypeThird(src, dst, payload, state)
			swtch(reply)
		} else if op == 3 {
			reply := msgTypeFourth(src, dst, payload, state)
			swtch(reply)
		} else if op == 4 {
			msgTypeFifth(src, dst, payload, state)
		}
	} else if op >= 10 && op < 20 {
		// 35 challenge protocol
		if op == 10 {
			reply := msgTypeEleventh(src, dst, payload, state)
			swtch(reply)
		} else if op == 11 {
			reply := msgTypeTwelfth(src, dst, payload, state)
			swtch(reply)
		} else if op == 12 {
			reply := msgTypeThirteenth(src, dst, payload, state)
			swtch(reply)
		} else if op == 13 {
			reply := msgTypeFourteenth(src, dst, payload, state)
			swtch(reply)
		} else if op == 14 {
			reply := msgTypeFifteenth(src, dst, payload, state)
			swtch(reply)
		} else if op == 15 {
			msgTypeSixteenth(src, dst, payload, state)
		}
	}
}

func Bob(payload []byte) {
	src, dst, op := parseMeta(payload)
	payload = payload[35:]
	state := bobState
	if op > 0 && op < 10 {
		// 34 challenge protocol
		if op == 1 {
			reply := msgTypeSecond(src, dst, payload, state)
			swtch(reply)
		} else if op == 2 {
			reply := msgTypeThird(src, dst, payload, state)
			swtch(reply)
		} else if op == 3 {
			reply := msgTypeFourth(src, dst, payload, state)
			swtch(reply)
		} else if op == 4 {
			msgTypeFifth(src, dst, payload, state)
		}
	} else if op >= 10 && op < 20 {
		// 35 challenge protocol
		if op == 10 {
			reply := msgTypeEleventh(src, dst, payload, state)
			swtch(reply)
		} else if op == 11 {
			reply := msgTypeTwelfth(src, dst, payload, state)
			swtch(reply)
		} else if op == 12 {
			reply := msgTypeThirteenth(src, dst, payload, state)
			swtch(reply)
		} else if op == 13 {
			reply := msgTypeFourteenth(src, dst, payload, state)
			swtch(reply)
		} else if op == 14 {
			reply := msgTypeFifteenth(src, dst, payload, state)
			swtch(reply)
		} else if op == 15 {
			msgTypeSixteenth(src, dst, payload, state)
		}
	}
}

func Eve(payload []byte) {
	src, dst, op := parseMeta(payload)
	payload = payload[35:]
	fmt.Printf("%s received op=%d\n", names[dst], op)
	newDst := ""
	if src == alice {
		newDst = bob
	} else {
		newDst = alice
	}
	state := eveState
	if op > 0 && op < 10 {
		// 34 challenge protocol
		if op == 1 {
			digits := decodeBigNums(payload, 3)
			p := digits[0]
			g := digits[1]
			state["p"] = p
			encoded := encodeBigNums(p, g, p)
			reply := wrapMsg(dst, newDst, 1, encoded)
			swtch(reply)
		} else if op == 2 {
			p := BN(state["p"])
			encoded := encodeBigNums(p)
			reply := wrapMsg(dst, newDst, 2, encoded)
			swtch(reply)
		} else if op == 3 || op == 4 {
			decoded := decodeByteSlices(payload, 2)
			ct := decoded[0]
			iv := decoded[1]

			// s=0 because p^a%p or p^b%p == 0
			s := big.NewInt(0)
			pt := decryptCBCAndStripPad(ct, iv, s)
			fmt.Printf("decrypted pt: %s\n", pt)
			reply := wrapMsg(dst, newDst, op, payload)
			swtch(reply)
		}
	} else if op >= 10 && op < 20 {
		// 35 challenge protocol
		if op == 10 {
			digits := decodeBigNums(payload, 2)
			p := digits[0]
			/*
			   with g=1, S=1
			   with g=p, S=0
			   with g=p-1, S=0
			*/
			g := p.Sub(p, big.NewInt(1))
			state["p"] = p
			state["g"] = g
			encoded := encodeBigNums(p, g)
			reply := wrapMsg(dst, newDst, 10, encoded)
			swtch(reply)
		} else if op == 11 {
			reply := wrapMsg(dst, newDst, 11, payload)
			swtch(reply)
		} else if op == 12 {
			/*
			   Alice:
			   A = g^a = ?
			   S = B^a = 1^a = 1

			   Bob:
			   B = 1^b = 1
			   S = A^b = ?

			   I don't see any other way for parties to
			   agree on the same key besides modifying A
			   as well.
			   The other option would be to impersonate
			   Bob as Eve and not engage Bob in coversation
			   at all, not sure if this qualifies as MITM
			   One more option is to somehow force both
			   parties to agree on same g, but that would
			   mean that the protocol description is wrong
			*/
			A := BN(state["p"])
			encoded := encodeBigNums(A)
			reply := wrapMsg(dst, newDst, 12, encoded)
			swtch(reply)
		} else if op == 13 {
			reply := wrapMsg(dst, newDst, 13, payload)
			swtch(reply)
		} else if op == 14 || op == 15 {
			decoded := decodeByteSlices(payload, 2)
			ct := decoded[0]
			iv := decoded[1]

			s := big.NewInt(0)
			pt := decryptCBCAndStripPad(ct, iv, s)
			fmt.Printf("eve decrypted pt: %s\n", pt)
			reply := wrapMsg(dst, newDst, op, payload)
			swtch(reply)
		}
	}
}

func ThirtyFourth() {
	payload := msgTypeFirst(alice, eve, []byte{}, aliceState)
	swtch(payload)
}

func ThirtyFifth() {
	payload := msgTypeTenth(alice, eve, []byte{}, aliceState)
	swtch(payload)
}

func ThirtySixth() {
	srp.Srp()
}

func ThirtySeventh() {
	//srp.SrpZeroA()
	//srp.SrpNA()
	srp.SrpNA2()
}

func ThirtyEighth() {
	srp.SrpDict()
}

type RSAPrivateKey struct {
	D *big.Int
	N *big.Int
}

type RSAPublicKey struct {
	E *big.Int
	N *big.Int
}

func BigSub(a, b *big.Int) *big.Int {
	return new(big.Int).Sub(a, b)
}

func BigMul(a, b *big.Int) *big.Int {
	return new(big.Int).Mul(a, b)
}

func BigMod(a, b *big.Int) *big.Int {
	return new(big.Int).Mod(a, b)
}

func EGCD(a, b *big.Int) (*big.Int, *big.Int, *big.Int) {
	// (GCD, Bézout coefficients)
	s := new(big.Int)
	oldS := big.NewInt(1)
	t := big.NewInt(1)
	oldT := new(big.Int)
	r := new(big.Int).Set(b)
	oldR := new(big.Int).Set(a)
	for r.Cmp(big.NewInt(0)) != 0 {
		quot := new(big.Int)
		quot.Div(oldR, r)
		// (old_r, r) := (r, old_r - quotient * r)
		tmp := BigSub(oldR, BigMul(quot, r))
		oldR = r
		r = tmp
		// (old_s, s) := (s, old_s - quotient * s)
		tmp = BigSub(oldS, BigMul(quot, s))
		oldS = s
		s = tmp
		// (old_t, t) := (t, old_t - quotient * t)
		tmp = BigSub(oldT, BigMul(quot, t))
		oldT = t
		t = tmp
	}
	return oldR, oldS, oldT
}

func ModInv(a, b *big.Int) (*big.Int, error) {
	g, x, _ := EGCD(a, b)
	if g.Cmp(big.NewInt(1)) == 0 {
		res := new(big.Int).Set(x)
		res.Mod(x, b)
		return res, nil
	} else {
		return new(big.Int), errors.New("no modinverse")
	}
}

func RSAEncrypt(key RSAPublicKey, msg *big.Int) *big.Int {
	return ExpInt(msg, key.E, key.N)
}

func RSADecrypt(key RSAPrivateKey, ct *big.Int) *big.Int {
	return ExpInt(ct, key.D, key.N)
}

func GenPrimes() (*big.Int, *big.Int) {
    bitLen := 1024
    a, _ := rand.Prime(rand.Reader, bitLen)
    b, _ := rand.Prime(rand.Reader, bitLen)
    return a, b
}

var RSAe = big.NewInt(3)

func RSAGenKeys() (RSAPublicKey, RSAPrivateKey) {
	e := new(big.Int).Set(RSAe)
	d := new(big.Int)
	n := new(big.Int)
	for true {
		p, q := GenPrimes()
		n.Mul(p, q)
		one := big.NewInt(1)
		pone := big.NewInt(0)
		pone.Sub(p, one)
		qone := big.NewInt(0)
		qone.Sub(q, one)
		et := new(big.Int)
		et.Mul(pone, qone)

		r, ok := ModInv(e, et)
		d = r
		if ok == nil {
			//fmt.Printf("primes: %v %v\n", p, q)
			break
		}
	}

	pub := RSAPublicKey{E: e, N: n}
	priv := RSAPrivateKey{D: d, N: n}

	return pub, priv
}

func ThirtyNinth() {
	pub, priv := RSAGenKeys()
	ct := RSAEncrypt(pub, big.NewInt(42))
	pt := RSADecrypt(priv, ct)
	fmt.Printf("%v\n", pt)

	s := "secret"
	pt2 := new(big.Int).SetBytes([]byte(s))
	ct2 := RSAEncrypt(pub, pt2)
	pt3 := RSADecrypt(priv, ct2)
	fmt.Printf("%v\n", string(pt3.Bytes()))
}

// I cheated and reused the cube root algorithm from stackoverflow
// I figured this is not really important when it comes to cryptography
// so... https://stackoverflow.com/a/51390715/1491475
func BigCbrt(i *big.Int) (cbrt *big.Int, rem *big.Int) {
    var (
        n0  = big.NewInt(0)
        n1  = big.NewInt(1)
        n2  = big.NewInt(2)
        n3  = big.NewInt(3)
    )
    var (
        guess   = new(big.Int).Div(i, n2)
        guessSq = new(big.Int)
        dx      = new(big.Int)
        absDx   = new(big.Int)
        minDx   = new(big.Int).Abs(i)
        cube    = new(big.Int)
        fx      = new(big.Int)
        fxp     = new(big.Int)
        step    = new(big.Int)
    )
    for {
        cube.Exp(guess, n3, nil)
        dx.Sub(i, cube)
        cmp := dx.Cmp(n0)
        if cmp == 0 {
            return guess, n0
        }

        fx.Sub(cube, i)
        guessSq.Exp(guess, n2, nil)
        fxp.Mul(n3, guessSq)
        step.Div(fx, fxp)
        if step.Cmp(n0) == 0 {
            step.Set(n1)
        }

        absDx.Abs(dx)
        switch absDx.Cmp(minDx) {
        case -1:
            minDx.Set(absDx)
        case 0:
            return guess, dx
        }

        guess.Sub(guess, step)
    }
}


func Fortieth() {
	pub0, _ := RSAGenKeys()
	pub1, _ := RSAGenKeys()
	pub2, _ := RSAGenKeys()

    s := "secret"

	pt := new(big.Int).SetBytes([]byte(s))

	ct0 := RSAEncrypt(pub0, pt)
	ct1 := RSAEncrypt(pub1, pt)
	ct2 := RSAEncrypt(pub2, pt)

    n0 := pub0.N
    n1 := pub1.N
    n2 := pub2.N

    ms0 := BigMul(n1, n2)
    ms1 := BigMul(n0, n2)
    ms2 := BigMul(n0, n1)

    r0, ok0 := ModInv(ms0, n0)
    if ok0 != nil {
        panic("damn")
    }

    r1, ok1 := ModInv(ms1, n1)
    if ok1 != nil {
        panic("damn")
    }

    r2, ok2 := ModInv(ms2, n2)
    if ok2 != nil {
        panic("damn")
    }

    res0 := BigMul(BigMul(ct0, ms0), r0)
    res1 := BigMul(BigMul(ct1, ms1), r1)
    res2 := BigMul(BigMul(ct2, ms2), r2)


    sum := new(big.Int)
    sum.Add(res0, res1)
    sum.Add(sum, res2)
    nSum := BigMul(BigMul(n0, n1), n2)

    result := new(big.Int).Mod(sum, nSum)
    res, _ := BigCbrt(result)

	fmt.Printf("%v\n", string(res.Bytes()))
}
