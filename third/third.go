package third

import (
	"cryptopals/first"
	"cryptopals/second"
	"encoding/base64"
	"encoding/binary"
	_ "encoding/hex"
	_ "errors"
	"fmt"
	_ "log"
	"math"
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

func Nineteenth(){
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
    maxLen := 0
    for _, ct := range cts {
        if ln := len(ct); ln > maxLen {
            maxLen = ln
        }
    }
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
