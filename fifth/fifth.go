package fifth

import (
	"bytes"
	"crypto/rand"
	"cryptopals/fifth/srp"
	"cryptopals/second"
	"cryptopals/sha1"
	"encoding/binary"
	"encoding/hex"
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
