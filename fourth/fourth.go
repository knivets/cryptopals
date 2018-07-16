package fourth

import (
	"cryptopals/first"
	"cryptopals/third"
	"fmt"
	"strings"
)

func EditCTRCiphertext(ct []byte,
	key []byte, nonce uint64, offset int, newtext byte) []byte {
	pt := third.DecryptCTR(ct, key, nonce)
	pt[offset] = newtext
	newCt := third.EncryptCTR(pt, key, nonce)
	return newCt
}

var CTRSharedKey []byte = first.GenSingleByteSlice(byte(10), 16)
var CTRSharedNonce uint64 = 0

func EditCTRAPICall(ct []byte, offset int, newtext byte) []byte {
	ct = EditCTRCiphertext(ct, CTRSharedKey, CTRSharedNonce, offset, newtext)
	return ct
}

func GetCTRPlaintext(ct []byte) []byte {
	pt := []byte{}
	for i := 0; i < len(ct); i++ {
		old := ct[i]
		for j := 0; j <= 256; j++ {
			tmpCt := EditCTRAPICall(ct, i, byte(j))
			if tmpCt[i] == old {
				pt = append(pt, byte(j))
				break
			}
		}
	}
	return pt
}

func userDataEncodeCTR(data string, key []byte, nonce uint64) []byte {
	prefix := "comment1=cooking%20MCs;userdata="
	suffix := ";comment2=%20like%20a%20pound%20of%20bacon"

	san := strings.Replace(data, ";", "", -1)
	san = strings.Replace(san, "=", "", -1)
	pt := []byte(prefix + san + suffix)
	//fmt.Printf("%q\n", pt)
	res := third.EncryptCTR(pt, key, nonce)
	return res
}

func userDataDecodeCTR(ciph []byte, key []byte, nonce uint64) bool {
	admin := false
	pt := third.DecryptCTR(ciph, key, nonce)
	fmt.Printf("%q\n", pt)
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

func RewriteCTR() {
	key := first.GenSingleByteSlice(byte(32), 16)
	nonce := uint64(0)
	in := []byte("aaadminttrue")
	ct := userDataEncodeCTR(string(in), key, nonce)
	modCt := []byte{}
	modCt = append([]byte{}, ct...)
	modCt[33] = byte(145)
	modCt[39] = byte(106)
	admin := userDataDecodeCTR(modCt, key, nonce)
	fmt.Printf("%t\n", admin)
}
