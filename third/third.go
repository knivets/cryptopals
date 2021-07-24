package third

import (
	"knivets.com/cryptopals/first"
	"knivets.com/cryptopals/second"
	"encoding/base64"
	"encoding/binary"
	_ "encoding/hex"
	_ "errors"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"reflect"
	"strconv"
	"strings"
	"time"
)

func CBCPaddingOracle(iv []byte, key []byte) []byte {
	payload := []string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}
	num := second.GenRandomNum(len(payload))
	pt := []byte(payload[num])
	pad := second.Pkcs7(pt, 16)
	ciph := second.EncryptCBC(pad, iv, key)
	return ciph
}

func decryptAndCheckPadding(ciph []byte, iv []byte, key []byte) bool {
	valid := false
	pad := second.DecryptCBC(ciph, iv, key)
	_, err := second.StripPkcs7(pad)
	if err == nil {
		valid = true
	}
	return valid
}

func producePaddingByte(dec byte, out int) byte {
	var fin byte
	for i := 0; i < 256; i++ {
		res := byte(i) ^ dec
		if res == byte(out) {
			fin = byte(i)
			break
		}
	}
	return fin
}

// expects 2 blocks: the one we're decoding (n), and n-1
func DecodeCBCBlock(blk, iv, key []byte) []byte {
	decr := []byte{}

	for i := 0; i < 16; i++ {
		block := append([]byte(nil), blk...)
		for j := 0; j < 256; j++ {
			block[15-i] = byte(j)
			if i > 0 {
				for k, dec := range decr {
					block[15-k] = producePaddingByte(dec, i+1)
				}
			} else {
				block[14] = byte(0)
			}
			valid := decryptAndCheckPadding(block, iv, key)
			if valid == true {
				dec := byte(j ^ (i + 1))
				decr = append(decr, dec)
				break
			}
		}
	}

	block := append([]byte(nil), blk...)
	pt := []byte{}
	for i := 0; i < len(decr); i++ {
		pt = append([]byte{decr[i] ^ block[15-i]}, pt...)
	}
	return pt
}

func EncryptCTR(blk, key []byte, nonce uint64) []byte {
	pt := make([]byte, 16)
	binary.LittleEndian.PutUint64(pt[0:8], nonce)
	count := int(math.Ceil(float64(len(blk)) / 16))
	keystream := []byte{}
	for i := 0; i < count; i++ {
		binary.LittleEndian.PutUint64(pt[8:16], uint64(i))
		keystream = append(keystream, second.EncryptECB(pt, key)...)
	}
	ct := first.XOR(blk, keystream[0:len(blk)])
	return ct
}

func DecryptCTR(blk, key []byte, nonce uint64) []byte {
	pt := EncryptCTR(blk, key, nonce)
	return pt
}

func getLongestSliceLen(slices [][]byte) int {
	maxLen := 0
	for _, slc := range slices {
		if ln := len(slc); ln > maxLen {
			maxLen = ln
		}
	}
	return maxLen
}

func BreakCTR() {
	nonce := 0
	key := first.GenSingleByteSlice(byte(64), 16)
	cts := [][]byte{}
	pts := []string{
		"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
		"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
		"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
		"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
		"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
		"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
		"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
		"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
		"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
		"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
		"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
		"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
		"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
		"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
		"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
		"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
		"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
		"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
		"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
		"U2hlIHJvZGUgdG8gaGFycmllcnM/",
		"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
		"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
		"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
		"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
		"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
		"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
		"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
		"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
		"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
		"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
		"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
		"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
		"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
		"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
		"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
		"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
	}
	for _, pt := range pts {
		dec, _ := base64.StdEncoding.DecodeString(pt)
		ct := EncryptCTR(dec, key, uint64(nonce))
		cts = append(cts, ct)
	}
	maxLen := getLongestSliceLen(cts)
	var bt byte
	potKey := []byte{}
	for j := 0; j < maxLen; j++ {
		score := 0
		for i := 0; i < 256; i++ {
			chars := []byte{}
			for _, ct := range cts {
				ln := len(ct)
				if j <= (ln - 1) {
					chars = append(chars, ct[j])
				}
			}
			dec := first.XOR(chars, first.GenSingleByteSlice(byte(i), len(chars)))
			curr := first.EnglishTextScore(dec)
			if curr > score {
				score = curr
				bt = byte(i)
			}
		}
		potKey = append(potKey, bt)
	}
	// got from pure brute force
	potKey[7] = byte(13)
	potKey[30] = byte(115)
	potKey[33] = byte(255)
	potKey[34] = byte(156)
	potKey[35] = byte(57)
	potKey[36] = byte(42)
	potKey[37] = byte(137)
	for _, ct := range cts {
		z := first.XOR(ct, potKey[0:len(ct)])
		fmt.Printf("%q\n", z)
	}
	fmt.Printf("%x\n", potKey)
}

func getPotentialKeysCTR(data []byte, size int) [][]byte {
	var potKeys [][]byte
	chunks := first.SplitBtsInChunks(data, size)
	transposed := first.TransposeChunks(chunks)
	var potKey []byte
	for _, chunk := range transposed {
		bt := first.SolveSingleCharXOR(chunk)
		potKey = append(potKey, bt.Bt)
	}
	potKeys = append(potKeys, potKey)
	return potKeys
}

func SolveRollingXORCTR(data []byte, size int) []byte {
	potKeys := getPotentialKeysCTR(data, size)
	score := 0
	key := []byte{}
	for _, potKey := range potKeys {
		res := first.RollingXOR(data, potKey)
		currScore := first.EnglishTextScore(res)
		if currScore > score {
			score = currScore
			key = potKey
		}
	}
	return key
}

func BreakCTRsecond() {
	data, err := ioutil.ReadFile("20.txt")
	if err != nil {
		log.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	lines = lines[0 : len(lines)-1]
	cts := [][]byte{}
	nonce := 0
	key := first.GenSingleByteSlice(byte(64), 16)
	for _, line := range lines {
		pt, _ := base64.StdEncoding.DecodeString(line)
		ct := EncryptCTR(pt, key, uint64(nonce))
		cts = append(cts, ct)
	}
	potKey := []byte{}
	maxLen := getLongestSliceLen(cts)
	for j := 0; j < maxLen; j++ {
		var bt byte
		score := 0
		chars := []byte{}
		for _, ct := range cts {
			ln := len(ct)
			if j <= (ln - 1) {
				chars = append(chars, ct[j])
			}
		}
		for i := 0; i < 256; i++ {
			dec := first.XOR(chars, first.GenSingleByteSlice(byte(i), len(chars)))
			curr := first.EnglishTextScore(dec)
			if curr > score {
				score = curr
				bt = byte(i)
			}
		}
		potKey = append(potKey, bt)
	}
	for _, ct := range cts {
		pt := first.XOR(ct, potKey)
		fmt.Printf("%q\n", pt)
	}
}

func BreakCTRthird() {
	data, err := ioutil.ReadFile("20.txt")
	if err != nil {
		log.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	lines = lines[0 : len(lines)-1]
	cts := [][]byte{}
	nonce := 0
	key := first.GenSingleByteSlice(byte(64), 16)
	for _, line := range lines {
		pt, _ := base64.StdEncoding.DecodeString(line)
		ct := EncryptCTR(pt, key, uint64(nonce))
		cts = append(cts, ct)
	}
	minLen := 0
	for _, ct := range cts {
		if ln := len(ct); minLen == 0 || ln < minLen {
			minLen = ln
		}
	}
	ciph := []byte{}
	for _, ct := range cts {
		ciph = append(ciph, ct[0:minLen]...)
	}
	key = SolveRollingXORCTR(ciph, minLen)
	key[0] = byte(173)
	for _, ct := range cts {
		pt := first.XOR(ct, key)
		fmt.Printf("%q\n", pt)
	}
}

func MT19937Init(seed uint32) []uint32 {
	state := []uint32{seed}
	for i := uint32(1); i < 624; i++ {
		prev := state[len(state)-1]
		elem := 0x6c078965*(prev^(prev>>30)) + i
		state = append(state, uint32(elem))
	}
	return state
}

func MT19937Regenerate(state []uint32) {
	for i := 0; i < 624; i++ {
		y := state[i] & 0x80000000
		y += state[(i+1)%624] & 0x7fffffff

		z := state[(i+397)%624]
		state[i] = z ^ (y >> 1)

		if (y % 2) != 0 {
			state[i] ^= 0x9908b0df
		}
	}
}

func MT19937(num int, seed uint32) []uint32 {
	res := []uint32{}
	state := MT19937Init(seed)
	index := len(state)
	for len(res) < num {
		if index >= len(state) {
			MT19937Regenerate(state)
			index = 0
		}
		//fmt.Printf("state: %d\n", state[index])
		el := MT19937Temper(state[index])
		//fmt.Printf("tempered: %d\n", el)
		res = append(res, el)
		index += 1
	}
	return res
}

func MT19937FromSlice(num int, seedState []uint32) []uint32 {
	res := []uint32{}
	state := seedState
	index := 0
	for len(res) < num {
		if index >= len(state) {
			MT19937Regenerate(state)
			index = 0
		}
		//fmt.Printf("state: %d\n", state[index])
		el := MT19937Temper(state[index])
		//fmt.Printf("tempered: %d\n", el)
		res = append(res, el)
		index += 1
	}
	return res
}

func MT19937Temper(y uint32) uint32 {
	y ^= y >> 11
	y ^= (y << 7) & 0x9d2c5680
	y ^= (y << 15) & 0xefc60000
	y ^= y >> 18
	return y
}

func MT19937Untemper(y uint32) uint32 {
	y = reverseRightShiftXor(y, 18)
	y = reverseFirstOp(y)
	y = reverseSecondOp(y)
	y = reverseRightShiftXor(y, 11)
	return y
}

func reverseRightShiftXor(y uint32, nm int) uint32 {
	iters := uint32(math.Ceil(float64(32) / float64(nm)))
	num := uint32(nm)
	binStr := strings.Repeat("1", int(num))
	mskInt, _ := strconv.ParseInt(binStr, 2, 32)
	mask := uint32(mskInt)

	res := uint32(0)
	msk := mask << (32 - num)
	res = y & msk
	for i := uint32(1); i < iters; i++ {
		maskShift := (32 - ((i + 1) * num))
		if maskShift >= 32 {
			maskShift = 0
		}
		msk := mask << maskShift
		rec := ((res >> num) ^ y)
		rs := rec & msk
		res |= rs
	}
	return res
}

func reverseSecondOp(y uint32) uint32 {
	binStr := strings.Repeat("1", 7)
	mskInt, _ := strconv.ParseInt(binStr, 2, 32)
	mask := uint32(mskInt)
	msk := uint32(0x9d2c5680)
	res := uint32(0)
	res |= y & mask
	res |= (y ^ ((res << 7) & msk)) & (mask << 7)
	res |= (y ^ ((res << 7) & msk)) & (mask << 14)
	res |= (y ^ ((res << 7) & msk)) & (mask << 21)
	res |= (y ^ ((res << 7) & msk)) & (mask << 25)
	return res
}

func reverseFirstOp(y uint32) uint32 {
	binStr := strings.Repeat("1", 15)
	mskInt, _ := strconv.ParseInt(binStr, 2, 32)
	mask := uint32(mskInt)
	msk := uint32(0xefc60000)
	res := uint32(0)
	res |= y & mask
	res |= (y ^ ((res << 15) & msk)) & (mask << 15)
	res |= (y ^ ((res << 15) & msk)) & (mask << 17)
	return res
}

func secondsToMiliSecs(sec int) int {
	return int(time.Duration(sec) * time.Second)
}

func MT19937CrackSeed() {
	sec := 40 + second.GenRandomNum(50)
	time.Sleep(time.Duration(secondsToMiliSecs(sec)))
	now := time.Now()
	seed := uint32(now.Unix())
	fmt.Printf("hidden seed: %d\n", seed)
	num := MT19937(1, seed)

	sec = 40 + second.GenRandomNum(30)
	time.Sleep(time.Duration(secondsToMiliSecs(sec)))
	later := time.Now()
	var result uint32
	for i := 0; i <= secondsToMiliSecs(1000); i++ {
		potSeed := uint32(later.Unix()) - uint32(i)
		cand := MT19937(1, potSeed)
		if cand[0] == num[0] {
			result = potSeed
			break
		}
	}
	fmt.Printf("discovered seed: %d\n", result)
}

func CloneMT19937() {
	orig := MT19937(1248, 0)
	state := []uint32{}
	for _, num := range orig[0:624] {
		res := MT19937Untemper(num)
		state = append(state, res)
	}
	cloned := MT19937FromSlice(1248, state)
	equal := reflect.DeepEqual(orig, cloned)
	fmt.Println(equal)
}

func MT19937Encrypt(pt []byte, key uint16) []byte {
	numbers := MT19937(len(pt), uint32(key))
	keystream := []byte{}
	for _, number := range numbers {
		keystream = append(keystream, byte(number))
	}

	return first.XOR(pt, keystream)
}

func MT19937Decrypt(ct []byte, key uint16) []byte {
	return MT19937Encrypt(ct, key)
}

func isPasswordTokenUnsecure(token []byte) bool {
	unsecure := false
	now := uint32(time.Now().Unix())
	hour := uint32(secondsToMiliSecs(3600))

	for i := uint32(0); i < hour; i++ {
		potSeed := now - i
		numbers := MT19937(10, potSeed)
		potToken := []byte{}
		for _, num := range numbers {
			potToken = append(potToken, byte(num))
		}
		unsecure = reflect.DeepEqual(potToken, token)
		if unsecure == true {
			break
		}
	}
	return unsecure
}

func CrackMTStreamCipher() {
	num := second.GenRandomNum(15)
	data := []byte{}
	for i := 0; i < num; i++ {
		chr := 65 + second.GenRandomNum(57)
		data = append(data, byte(chr))
	}
	data = append(data, first.GenSingleByteSlice(byte('A'), 14)...)
	seed := second.GenRandomNum(10000)
	ct := MT19937Encrypt(data, uint16(seed))
	for i := 0; i <= 65536; i++ {
		potSeed := uint32(i)
		numbers := MT19937(len(ct), potSeed)
		bts := []byte{}
		for _, num := range numbers {
			bts = append(bts, byte(num))
		}
		res := first.XOR(bts, ct)
		expectedPt := first.GenSingleByteSlice(byte('A'), 14)
		equal := false
		for j := 0; j < len(res); j++ {
			ptIndex := len(expectedPt) - (j + 1)
			if ptIndex >= 0 {
				resEl := res[len(res)-(j+1)]
				ptEl := expectedPt[ptIndex]
				if ptEl != resEl {
					break
				} else {
					if ptIndex == 0 {
						equal = true
					}
				}
			}
		}
		if equal == true {
			pt := MT19937Decrypt(ct, uint16(potSeed))
			fmt.Printf("secret seed is: %d\n", seed)
			fmt.Printf("secret pt is: %s\n", data)
			fmt.Printf("discovered seed is: %d\n", potSeed)
			fmt.Printf("discovered pt is: %s\n", pt)
		}
	}

	// part 2 of the ex
	now := time.Now().Unix()
	numbers := MT19937(10, uint32(now))
	token := []byte{}
	for _, num := range numbers {
		token = append(token, byte(num))
	}
	unsecure := isPasswordTokenUnsecure(token)
	fmt.Printf("is token a MT seeded with current time? %t\n", unsecure)
}
