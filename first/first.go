package first

import (
	"crypto/aes"
	"cryptopals/ecb"
	"encoding/base64"
	"encoding/hex"
	"log"
	"math"
	"sort"
)

func HexToBase64(src string) []byte {
	str, err := hex.DecodeString(src)
	if err != nil {
		log.Fatal(err)
	}
	res := base64.StdEncoding.EncodeToString(str)
	return []byte(res)
}

func XOR(first []byte, second []byte) []byte {
	if len(first) != len(second) {
		log.Fatal("XOR expects two equal length buffers")
	}
	res := make([]byte, len(first))
	for i := 0; i < len(first); i++ {
		res[i] = first[i] ^ second[i]
	}
	return res
}

func englishTextScore(data []byte) int {
	chrs := "etaoin shrdluETAOIN SHRDLU"
	score := 0
	for _, bt := range data {
		var pop bool
		for _, chr := range chrs {
			if bt == byte(chr) {
				pop = true
				break
			}
		}
		if pop {
			score += 10
		} else {
			score += 1
		}
	}
	return score
}

type ByteScore struct {
	Bt    byte
	Score int
}

func SolveSingleCharXOR(src []byte) ByteScore {
	var scores []ByteScore
	for i := 0; i <= 255; i++ {
		bt := byte(i)
		key := GenSingleByteSlice(bt, len(src))
		res := XOR(src, key)
		score := englishTextScore(res)
		scores = append(scores, ByteScore{bt, score})
	}
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].Score > scores[j].Score
	})
	if len(scores) > 0 {
		return scores[0]
	} else {
		return ByteScore{}
	}
}

func GenSingleByteSlice(bt byte, ln int) []byte {
	var key []byte
	for i := 0; i < ln; i++ {
		key = append(key, bt)
	}
	return key
}

func TakeHighestScoreStr(strs []string) (int, []byte) {
	score := 0
	var fin []byte
	for _, str := range strs {
		hx, _ := hex.DecodeString(str)
		res := SolveSingleCharXOR(hx)
		if res.Score > score {
			score = res.Score
			key := GenSingleByteSlice(res.Bt, len(hx))
			dec := XOR(hx, key)
			fin = dec
		}
	}
	return score, fin
}

func RollingXOR(txt []byte, key []byte) []byte {
	res := make([]byte, len(txt))
	counter := 0
	for i, c := range txt {
		res[i] = c ^ key[counter]
		if counter < len(key)-1 {
			counter += 1
		} else {
			counter = 0
		}
	}
	return res
}

func hammDist(first []byte, second []byte) int {
	positions := []byte{1, 2, 4, 8, 16, 32, 64, 128}
	diff := XOR(first, second)
	total := 0
	for _, bt := range diff {
		count := 0
		for _, pos := range positions {
			if bt&pos == pos {
				count += 1
			}
		}
		total += count
	}
	return total
}

func getIndices(ln, keysize, i int) (int, int) {
	var first int
	var second int
	if first = i * keysize; first > ln {
		first = ln
	}
	if second = (i + 1) * keysize; second > ln {
		second = ln
	}
	return first, second
}

type KeySizeScore struct {
	Size  int
	Score float32
}

func getKeySize(data []byte) []KeySizeScore {
	var result []KeySizeScore
	for keysize := 2; keysize <= 40; keysize++ {
		scaled := keysize * 10 // improves the search
		firstSt, firstFn := getIndices(len(data), scaled, 0)
		secondSt, secondFn := getIndices(len(data), scaled, 1)
		first := data[firstSt:firstFn]
		second := data[secondSt:secondFn]
		dst := float32(hammDist(first, second)) / float32(keysize)
		result = append(result, KeySizeScore{keysize, dst})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Score < result[j].Score
	})
	return result
}

func SplitBtsInChunks(data []byte, size int) [][]byte {
	var res [][]byte
	count := int(math.Ceil(float64(len(data)) / float64(size)))
	for i := 0; i < count; i++ {
		first, second := getIndices(len(data), size, i)
		res = append(res, data[first:second])
	}
	return res
}

func transposeChunks(chunks [][]byte) [][]byte {
	var res [][]byte
	for j := 0; j < len(chunks[0]); j++ {
		var bt []byte
		for i := 0; i < len(chunks); i++ {
			if j < len(chunks[i]) {
				bt = append(bt, chunks[i][j])
			}
		}
		res = append(res, bt)
	}
	return res
}

func getPotentialKeys(data []byte) [][]byte {
	sizes := getKeySize(data)
	var potKeys [][]byte
	for _, size := range sizes[0:2] {
		chunks := SplitBtsInChunks(data, size.Size)
		transposed := transposeChunks(chunks)
		var potKey []byte
		for _, chunk := range transposed {
			bt := SolveSingleCharXOR(chunk)
			potKey = append(potKey, bt.Bt)
		}
		potKeys = append(potKeys, potKey)
	}
	return potKeys
}

func SolveRollingXOR(data []byte) []byte {
	potKeys := getPotentialKeys(data)
	score := 0
	key := []byte{}
	for _, potKey := range potKeys {
		res := RollingXOR(data, potKey)
		currScore := englishTextScore(res)
		if currScore > score {
			score = currScore
			key = potKey
		}
	}
	return key
}

func DetectECB(data []byte) bool {
	status := false
	res := map[string]int{}
	chunks := SplitBtsInChunks(data, 16)
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

func DecryptECB(ciph []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	pt := make([]byte, len(ciph))
	mode := ecb.NewECBDecrypter(block)
	mode.CryptBlocks(pt, ciph)
	return pt
}
