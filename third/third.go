package third

import (
	_ "cryptopals/first"
	"cryptopals/second"
	_ "encoding/base64"
	_ "encoding/hex"
	_ "errors"
	_ "fmt"
	_ "log"
	_ "strings"
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
