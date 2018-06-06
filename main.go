package main

import (
	"cryptopals/first"
	"cryptopals/second"
	"cryptopals/third"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
)

func First() {
	hx := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	res := first.HexToBase64(hx)
	fmt.Printf("%s\n", res)
}

func Second() {
	hx1, _ := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	hx2, _ := hex.DecodeString("686974207468652062756c6c277320657965")
	res2 := hex.EncodeToString(first.XOR(hx1, hx2))
	fmt.Printf("%s\n", res2)
}

func Third() {
	hx, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	res := first.SolveSingleCharXOR(hx)
	key := first.GenSingleByteSlice(res.Bt, len(hx))
	res2 := first.XOR(hx, key)
	fmt.Printf("%s\n", res2)
}

func Fourth() {
	data, err := ioutil.ReadFile("4.txt")
	if err != nil {
		log.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	score, fin := first.TakeHighestScoreStr(lines)
	fmt.Printf("%d %s", score, fin)
}

func Fifth() {
	txt := []byte(`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`)
	key := []byte("ICE")
	res := first.RollingXOR(txt, key)
	z := hex.EncodeToString(res)
	x := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	fmt.Println(z, z == x)
}

func Sixth() {
	data, err := ioutil.ReadFile("6.txt")
	if err != nil {
		log.Fatal(err)
	}
	res, _ := base64.StdEncoding.DecodeString(string(data))
	key := first.SolveRollingXOR(res)
	pt := first.RollingXOR(res, key)
	fmt.Println(string(key))
	fmt.Println(string(pt))
}

func Seventh() {
	key := []byte("YELLOW SUBMARINE")
	data, err := ioutil.ReadFile("7.txt")
	if err != nil {
		log.Fatal(err)
	}
	ciph, _ := base64.StdEncoding.DecodeString(string(data))
	pt := first.DecryptECB(ciph, key)
	fmt.Printf("%v", string(pt))
}

func Eigth() {
	data, err := ioutil.ReadFile("8.txt")
	if err != nil {
		log.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	ecbLines := []string{}
	for _, line := range lines[0 : len(lines)-1] {
		bts, _ := hex.DecodeString(line)
		res := first.DetectECB(bts)
		if res == true {
			ecbLines = append(ecbLines, line)
		}
	}
	fmt.Println(ecbLines)
}

func Ninth() {
	res := second.Pkcs7([]byte("YELLOW SUBMARINE"), 20)
	fmt.Printf("%q\n", string(res))
}

func Tenth() {
	data, err := ioutil.ReadFile("10.txt")
	if err != nil {
		log.Fatal(err)
	}
	ct, _ := base64.StdEncoding.DecodeString(string(data))

	key := []byte("YELLOW SUBMARINE")
	iv := first.GenSingleByteSlice(byte(0), 16)
	res := second.DecryptCBC(ct, iv, key)
	fmt.Printf("%s\n", string(res))
}

func Eleventh() {
	ecb := second.IsBlockECB(second.EncryptionOracle)
	if ecb == true {
		fmt.Println("The block mode is ECB")
	} else {
		fmt.Println("The block mode is CBC")
	}
}

func Twelfth() {
	block := second.DecodeECBAESBlock()
	fmt.Printf("The plaintext is: \n\n%s\n", string(block))
}

func Thirteenth() {
	key := first.GenSingleByteSlice(byte(127), 16)
	rwr := second.MakeAdminProfile(key)
	dec := second.DecryptProfile(rwr, key)
	fmt.Printf("%q\n", dec)
}

func Fourteenth() {
	res := second.DecodeECBAESBlockWithPrefix()
	fmt.Printf("%s\n", res)
}

func Fifteenth() {
	pt1 := []byte("ICE ICE BABY\x04\x04\x04\x04")
	str1, _ := second.StripPkcs7(pt1)
	fmt.Printf("stripped: %q\n", str1)
	pt2 := []byte("ICE ICE BABY\x05\x05\x05\x05")
	str2, _ := second.StripPkcs7(pt2)
	fmt.Printf("stripped: %q\n", str2)
	pt3 := []byte("ICE ICE BABY\x01\x02\x03\x04")
	str3, _ := second.StripPkcs7(pt3)
	fmt.Printf("stripped: %q\n", str3)
}

func Sixteenth() {
	second.RewriteCBC()
}

func Seventeenth() {
	key := first.GenSingleByteSlice(byte(48), 16)
	iv := first.GenSingleByteSlice(byte(96), 16)
	ciph := third.CBCPaddingOracle(iv, key)
	pt := []byte{}
	ln := len(ciph)
	i := 0
	for true {
		if end := ln - 32 - (i * 16); end >= 0 {
			start := ln - (i * 16)
			blk := ciph[end:start]
			dec := third.DecodeCBCBlock(blk, iv, key)
			pt = append(dec, pt...)
			i++
		} else {
			break
		}
	}
	frst := append([]byte{}, iv...)
	frst = append(frst, ciph[0:16]...)
	dec := third.DecodeCBCBlock(frst, iv, key)
	pt = append(dec, pt...)
	fmt.Printf("plaintext is: %q\n", pt)
}

func main() {
	Seventeenth()
}
