package second

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"log"
	"math/big"
	"strings"
	"cryptopals/ecb"
	"cryptopals/first"
)

func Pkcs7(block []byte, size int) []byte {
	num := len(block) % size
	if num != 0 {
		num = size - num
	}
	for i := 0; i < num; i++ {
		block = append(block, byte(num))
	}
	return block
}

func encryptECB(ciph []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	pt := make([]byte, len(ciph))
	mode := ecb.NewECBEncrypter(block)
	mode.CryptBlocks(pt, ciph)
	return pt
}

func encryptCBC(pt []byte, iv []byte, key []byte) []byte {
	chunks := first.SplitBtsInChunks(pt, 16)
	blocks := []byte{}
	ciph := iv
	for _, chunk := range chunks {
		if len(chunk) < 16 {
			chunk = Pkcs7(chunk, 16)
		}
		section := first.XOR(ciph, chunk)
		ciph = encryptECB(section, key)
		blocks = append(blocks, ciph...)
	}
	return blocks
}

func DecryptCBC(ct []byte, iv []byte, key []byte) []byte {
	chunks := first.SplitBtsInChunks(ct, 16)
	blocks := []byte{}

	for i := len(chunks) - 1; i >= 0; i-- {
		section := first.DecryptECB(chunks[i], key)
		pt := []byte{}
		if i-1 < 0 {
			pt = first.XOR(section, iv)
		} else {
			pt = first.XOR(section, chunks[i-1])
		}
		blocks = append(pt, blocks...)
	}
	return blocks
}

func genRandomBytes(num int) []byte {
	bts := make([]byte, num)
	rand.Read(bts)
	return bts
}

func genRandomNum(num int) int {
	res, _ := rand.Int(rand.Reader, big.NewInt(int64(num)))
	return int(res.Int64())
}

func detectCBC(data []byte) bool {
	status := false
	return status
}

func EncryptionOracle(data []byte) []byte {
	key := genRandomBytes(16)
	startCount := 5 + genRandomNum(6)
	endCount := 5 + genRandomNum(6)
	startBts := genRandomBytes(startCount)
	endBts := genRandomBytes(endCount)
	mode := genRandomNum(2)
	pt := startBts
	pt = append(pt, data...)
	pt = append(pt, endBts...)
	pt = Pkcs7(pt, 16)
	res := []byte{}
	if mode == 0 {
		res = encryptECB(pt, key)
	} else {
		iv := genRandomBytes(16)
		res = encryptCBC(pt, iv, key)
	}
	return res
}

func detectECB(data []byte) bool {
	status := false
	res := map[string]int{}
	chunks := first.SplitBtsInChunks(data, 16)
	for _, chunk := range chunks {
		key := hex.EncodeToString(chunk)
		if val, ok := res[key]; ok {
			val += 1
			res[key] = val
		} else {
			res[key] = 1
		}
	}
	for _, val := range res {
		if val > 1 {
			status = true
		}
	}
	return status
}

func IsBlockECB(fn func([]byte) []byte) bool {
	pt := []byte("YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE")
	ct := fn(pt)
	status := detectECB(ct)
	return status
}

func ECBOracle(data []byte) []byte {
	key := first.GenSingleByteSlice(byte(127), 16)
	bs64 := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
		"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
		"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
		"YnkK"
	unknown, _ := base64.StdEncoding.DecodeString(bs64)
	pt := data
	pt = append(pt, unknown...)
	pt = Pkcs7(pt, 16)
	res := encryptECB(pt, key)
	return res
}

func DecodeECBAESBlock() []byte {
	res := []byte{}
	blk := len(ECBOracle([]byte{}))

	for j := blk - 1; j >= 0; j-- {
		pt := first.GenSingleByteSlice(byte(0), blk)
		dict := map[string]byte{}
		if j < blk-1 {
			offset := blk - 2
			for l := len(res) - 1; l >= 0; l-- {
				pt[offset] = res[l]
				offset -= 1
			}
		}
		for i := 0; i < 256; i++ {
			pt[blk-1] = byte(i)
			ct := ECBOracle(pt)
			hx := hex.EncodeToString(ct[0:blk])
			dict[hx] = byte(i)
		}
		mod := pt[0:j]
		ct := ECBOracle(mod)
		hx := hex.EncodeToString(ct[0:blk])
		res = append(res, dict[hx])
	}
	return res
}

// workaround to have a deterministic element order
type KV struct {
	key string
	val string
}

func parseKVStr(data string) []KV {
	res := []KV{}
	pairs := strings.Split(data, "&")
	for _, pair := range pairs {
		kv := strings.Split(pair, "=")
		res = append(res, KV{key: kv[0], val: kv[1]})
	}
	return res
}

func profileFor(email string) string {
	data := []KV{
		KV{key: "uid", val: "10"},
		KV{key: "role", val: "user"},
	}
	san := strings.Replace(email, "&", "", -1)
	san = strings.Replace(san, "=", "", -1)
	data = append([]KV{KV{key: "email", val: san}}, data...)
	pairs := []string{}
	for _, kv := range data {
		pairs = append(pairs, kv.key+"="+kv.val)
	}

	return strings.Join(pairs, "&")
}

func encryptProfile(email string, key []byte) []byte {
	pt := profileFor(email)
	pad := Pkcs7([]byte(pt), 16)
	res := encryptECB(pad, key)
	return res
}

func DecryptProfile(ct []byte, key []byte) []KV {
	pt := first.DecryptECB(ct, key)
	ob := parseKVStr(string(pt))
	return ob
}

func produceAdminBlk(key []byte, padding int) []byte {
	in := []byte("bbbbbbbbbbadmin")
	in = append(in, first.GenSingleByteSlice(byte(padding), padding)...)
	enc := encryptProfile(string(in), key)
	blk := enc[16:32]
	return blk
}

func MakeAdminProfile(key []byte) []byte {
	in := []byte("max@gmail.com")
	enc := encryptProfile(string(in), key)
	blk := produceAdminBlk(key, 11)
	rwr := enc[0 : len(enc)-16]
	rwr = append(rwr, blk...)
	return rwr
}