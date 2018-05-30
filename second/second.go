package second

import (
	"crypto/aes"
	"crypto/rand"
	"cryptopals/ecb"
	"cryptopals/first"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strings"
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

func ECBPrefixOracle(data []byte, prefix []byte) []byte {
	key := first.GenSingleByteSlice(byte(127), 16)
	bs64 := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
		"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
		"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
		"YnkK"
	unknown, _ := base64.StdEncoding.DecodeString(bs64)
	unknown = []byte("Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n testbb")
	pt := prefix
	pt = append(pt, data...)
	pt = append(pt, unknown...)
	pt = Pkcs7(pt, 16)
	res := encryptECB(pt, key)
	return res
}

func PrintChunks(data []byte, size int) {
	chunks := first.SplitBtsInChunks(data, size)
	for i, chunk := range chunks {
		fmt.Printf("%d: %x\n", i, chunk)
	}
}

func getNumOfDuplicateBlocks(data []byte) int {
	chunks := first.SplitBtsInChunks(data, 16)
	blks := map[string]int{}
	count := 1
	for _, chunk := range chunks {
		hx := hex.EncodeToString(chunk)
		if _, ok := blks[hx]; ok {
			count += 1
		} else {
			blks[hx] = 1
		}
	}
	return count
}

func guessInputPrefixLength(prefix []byte) int {
	// arbitrary number to produce a high level of dups
	num := 1024
	in := first.GenSingleByteSlice(byte(0), num)
	res := ECBPrefixOracle(in, prefix)
	dup := getNumOfDuplicateBlocks(res)
	// low chance that there are 20 16-byte blocks of
	// exact plaintext
	if dup > 20 {
		// reducing prefix to a single block
		// probably breaks in case we have duplicate
		// plaintext blocks, though not a problem to
		// handle this case
		for i := num; i >= 0; i-- {
			in := first.GenSingleByteSlice(byte(0), i)
			res := ECBPrefixOracle(in, prefix)
			nwDp := getNumOfDuplicateBlocks(res)
			if nwDp == 1 {
				num = i
				break
			}
		}
	}
	return num + 1
}

func getBlkOffset(inputPrefix int, prefix []byte) int {
	in := first.GenSingleByteSlice(byte(0), inputPrefix)
	res := ECBPrefixOracle(in, prefix)
	chunks := first.SplitBtsInChunks(res, 16)
	blks := map[string]int{}
	offset := 0
	for i, chunk := range chunks {
		hx := hex.EncodeToString(chunk)
		if _, ok := blks[hx]; ok {
			offset = (i + 1) * 16
		} else {
			blks[hx] = 1
		}
	}
	return offset
}

func getBlkSize(inputOffset, blkOffset int, prefix []byte) int {
	in := first.GenSingleByteSlice(byte(0), inputOffset)
	res := ECBPrefixOracle(in, prefix)
	return len(res) - blkOffset
}

func DecodeECBAESBlockWithPrefix() []byte {
	startCount := 5 + genRandomNum(64)
	startBts := genRandomBytes(startCount)
	res := []byte{}
	inputOffset := guessInputPrefixLength(startBts)
	blkOffset := getBlkOffset(inputOffset, startBts)
	blk := getBlkSize(inputOffset, blkOffset, startBts)
	/*fmt.Printf("input offset: %d\n", inputOffset)
	fmt.Printf("blk offset: %d\n", blkOffset)
	fmt.Printf("block length: %d\n\n", blk)*/

	for j := blk - 1; j >= 0; j-- {
		pt := first.GenSingleByteSlice(byte(0), inputOffset+blk)
		dict := map[string]byte{}
		if j < blk-1 {
			offset := blk - 2
			for l := len(res) - 1; l >= 0; l-- {
				pt[inputOffset+offset] = res[l]
				offset -= 1
			}
		}
		for i := 0; i < 256; i++ {
			pt[inputOffset+blk-1] = byte(i)
			ct := ECBPrefixOracle(pt, startBts)
			hx := hex.EncodeToString(ct[blkOffset : blkOffset+blk])
			dict[hx] = byte(i)
		}
		mod := pt[0 : inputOffset+j]
		ct := ECBPrefixOracle(mod, startBts)
		hx := hex.EncodeToString(ct[blkOffset : blkOffset+blk])
		res = append(res, dict[hx])
	}
	return res
}

func StripPkcs7(data []byte) ([]byte, error) {
	stripped := data
	padding := data[len(data)-1]
	paddingInt := int(padding)
	if paddingInt < 16 {
		for i := 0; i < paddingInt; i++ {
			pos := len(data) - 1 - i
			if data[pos] != padding {
				return []byte{}, errors.New("wrong padding")
			}
			stripped = stripped[:pos]
		}
	}
	return stripped, nil
}

func userDataEncodeCBC(data string, iv []byte, key []byte) []byte {
	prefix := "comment1=cooking%20MCs;userdata="
	suffix := ";comment2=%20like%20a%20pound%20of%20bacon"

	san := strings.Replace(data, ";", "", -1)
	san = strings.Replace(san, "=", "", -1)
	pt := prefix + san + suffix
	pad := Pkcs7([]byte(pt), 16)
	fmt.Printf("%q\n", pad)
	res := encryptCBC(pad, iv, key)
	return res
}

func userDataDecodeCBC(ciph []byte, iv []byte, key []byte) bool {
	admin := false
	pt := DecryptCBC(ciph, iv, key)
	fmt.Printf("%q\n", pt)
	//pt, _ = StripPkcs7(pt)
	kvs := [][]string{}
	pairs := strings.Split(string(pt), ";")
	for _, pair := range pairs {
		kv := strings.Split(pair, "=")
		kvs = append(kvs, kv)
	}
	for _, kv := range kvs {
		if len(kv) > 1 {
			if strings.Contains(kv[0], "admin") {
				if kv[1] == "true" {
					admin = true
				}
			}
		}
	}
	return admin
}

func Sixteenth() {
	key := first.GenSingleByteSlice(byte(32), 16)
	iv := first.GenSingleByteSlice(byte(64), 16)
	in := first.GenSingleByteSlice(byte('a'), 33)
	in = append(in, []byte("adminttrue")...)
	res := userDataEncodeCBC(string(in), iv, key)
	res[48] = byte(60)
	res[54] = byte(254)
	admin := userDataDecodeCBC(res, iv, key)
	fmt.Printf("%t\n", admin)
}
