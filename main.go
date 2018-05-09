package main

import (
	"fmt"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"math"
    "sort"
	"log"
    "io/ioutil"
    "crypto/aes"
    "cryptopals/ecb"
)

func hexToBase64(src string) []byte {
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
    Bt byte
    Score int
}

func solveSingleCharXOR(src []byte) ByteScore {
	var scores []ByteScore
	for i := 0; i <= 255; i++ {
        bt := byte(i)
		key := genSingleByteKey(bt, len(src))
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

func genSingleByteKey(bt byte, ln int) []byte {
    var key []byte
    for i := 0; i < ln; i++ {
        key = append(key, bt)
    }
    return key
}

func takeHighestScoreStr(strs []string) (int, []byte) {
    score := 0
    var fin []byte
    for _, str := range strs {
        hx, _ := hex.DecodeString(str)
        res := solveSingleCharXOR(hx)
        if res.Score > score {
            score = res.Score
            key := genSingleByteKey(res.Bt, len(hx))
            dec := XOR(hx, key)
            fin = dec
        }
    }
    return score, fin
}

func rollingXOR(txt []byte, key []byte) []byte{
    res := make([]byte, len(txt))
    counter := 0
    for i, c := range txt {
        res[i] = c ^ key[counter]
        if counter < len(key) - 1 {
            counter += 1
        } else {
            counter = 0
        }
    }
    return res
}

func hammDist(first []byte, second []byte) int {
    positions := []byte{1,2,4,8,16,32,64,128}
    diff := XOR(first, second)
    total := 0
    for _, bt := range diff {
        count := 0
        for _, pos := range positions {
            if bt & pos == pos {
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
    if first = i*keysize; first > ln {
        first = ln
    }
    if second = (i+1)*keysize; second > ln {
        second = ln
    }
    return first, second
}

type KeySizeScore struct {
    Size int
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

func splitBtsInChunks(data []byte, size int) [][]byte {
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
        chunks := splitBtsInChunks(data, size.Size)
        transposed := transposeChunks(chunks)
        var potKey []byte
        for _, chunk := range transposed {
            bt := solveSingleCharXOR(chunk)
            potKey = append(potKey, bt.Bt)
        }
        potKeys = append(potKeys, potKey)
    }
    return potKeys
}

func solveRollingXOR(data []byte) []byte {
    potKeys := getPotentialKeys(data)
    score := 0
    key := []byte{}
    for _, potKey := range potKeys {
        res := rollingXOR(data, potKey)
        currScore := englishTextScore(res)
        if currScore > score {
            score = currScore
            key = potKey
        }
    }
    return key
}

func pkcs7(block []byte, size int) []byte {
    num := len(block) % size
    if num != 0 {
        num = size - num
    }
    for i := 0; i < num; i++ {
        block = append(block, byte(num))
    }
    return block
}

func decryptECB(ciph []byte, key []byte) []byte {
    block, err := aes.NewCipher(key)
    if err != nil {
        log.Fatal(err)
    }
    pt := make([]byte, len(ciph))
    mode := ecb.NewECBDecrypter(block)
    mode.CryptBlocks(pt, ciph)
    return pt
}

type ChunkCount struct {
    Lines []string
    Count int
}

func detectCBC(lines []string) map[string]ChunkCount {
    res := map[string]ChunkCount{}
    for _, line := range lines[0:len(lines)-1] {
        bt, _ := hex.DecodeString(line)
        chunks := splitBtsInChunks(bt, 16)
        nw := false
        for _, chunk := range chunks {
            hx := hex.EncodeToString(chunk)
            if val, ok := res[hx]; ok {
                val.Count += 1
                if nw == false {
                    val.Lines = append(val.Lines, line)
                    nw = true
                }
                res[hx] = val
            } else {
                res[hx] = ChunkCount{Lines: []string{line}, Count: 1}
                nw = true
            }
        }
    }
    filtered := map[string]ChunkCount{}
    for key, val := range res {
        if val.Count > 1 {
            filtered[key] = val
        }
    }

    return filtered
}

func first() {
	hx := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	res := hexToBase64(hx)
	fmt.Printf("%s\n", res)
}

func second() {
	hx1, _ := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	hx2, _ := hex.DecodeString("686974207468652062756c6c277320657965")
	res2 := hex.EncodeToString(XOR(hx1, hx2))
	fmt.Printf("%s\n", res2)
}

func third() {
	hx, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	res := solveSingleCharXOR(hx)
	key := genSingleByteKey(res.Bt, len(hx))
	res2 := XOR(hx, key)
	fmt.Printf("%s\n", res2)
}

func fourth() {
    data, err := ioutil.ReadFile("4.txt")
    if err != nil {
        log.Fatal(err)
    }
    lines := strings.Split(string(data), "\n")
    score, fin := takeHighestScoreStr(lines)
    fmt.Printf("%d %s", score, fin)
}

func fifth() {
    txt := []byte(`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`)
    key := []byte("ICE")
    res := rollingXOR(txt, key)
    z := hex.EncodeToString(res)
    x := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    fmt.Println(z, z == x)
}

func sixth() {
    data, err := ioutil.ReadFile("6.txt")
    if err != nil {
        log.Fatal(err)
    }
    res, _ := base64.StdEncoding.DecodeString(string(data))
    key := solveRollingXOR(res)
    pt := rollingXOR(res, key)
    fmt.Println(string(key))
    fmt.Println(string(pt))
}

func seventh() {
    key := []byte("YELLOW SUBMARINE")
    data, err := ioutil.ReadFile("7.txt")
    if err != nil {
        log.Fatal(err)
    }
    ciph, _ := base64.StdEncoding.DecodeString(string(data))
    pt := decryptECB(ciph, key)
    fmt.Printf("%v", string(pt))
}

func eigth() {
    data, err := ioutil.ReadFile("8.txt")
    if err != nil {
        log.Fatal(err)
    }
    lines := strings.Split(string(data), "\n")
    res := detectCBC(lines)
    fmt.Println(res)
}

func ninth() {
    res := pkcs7([]byte("YELLOW SUBMARINE"), 20)
    fmt.Printf("%q\n", string(res))
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

func encryptCBC(pt []byte, iv []byte, key []byte) []byte{
    chunks := splitBtsInChunks(pt, 16)
    blocks := []byte{}
    ciph := iv
    for _, chunk := range chunks {
        if len(chunk) < 16 {
            chunk = pkcs7(chunk, 16)
        }
        section := XOR(ciph, chunk)
        ciph = encryptECB(section, key)
        blocks = append(blocks, ciph...)
    }
    return blocks
}

func decryptCBC(ct []byte, iv []byte, key []byte) []byte{
    chunks := splitBtsInChunks(ct, 16)
    blocks := []byte{}

    for i := len(chunks)-1; i >= 0; i-- {
        section := decryptECB(chunks[i], key)
        pt := []byte{}
        if i-1 < 0 {
            pt = XOR(section, iv)
        } else {
            pt = XOR(section, chunks[i-1])
        }
        blocks = append(pt, blocks...)
    }
    return blocks
}

func tenth() {
    data, err := ioutil.ReadFile("10.txt")
    if err != nil {
        log.Fatal(err)
    }
    ct, _ := base64.StdEncoding.DecodeString(string(data))

    key := []byte("YELLOW SUBMARINE")
    iv := genSingleByteKey(byte(0), 16)
    res := decryptCBC(ct, iv, key)
    fmt.Printf("%s\n", string(res))
}

func main() {
    tenth()
}
