package fourth

import (
	"cryptopals/first"
	"cryptopals/second"
	"cryptopals/sha1"
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

func checkForASCIIValues(pt []byte) error {
	for _, chr := range pt {
		intVal := int(chr)
		if intVal > 127 {
			return fmt.Errorf("wrong ascii value: %c in message %s", chr, pt)
		}
	}
	return nil
}

func userDataDecodeCBCWithChecks(ciph []byte, iv []byte, key []byte) (bool, error) {
	admin := false
	pt := second.DecryptCBC(ciph, iv, key)
	//pt, _ = second.StripPkcs7(pt)
	err := checkForASCIIValues(pt)
	if err != nil {
		return false, err
	}
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
	return admin, nil
}

func ExtractKeyFromCBCIV() {
	key := []byte("YELLOW SUBMARINE")
	iv := key
	res := second.UserDataEncodeCBC("a", iv, key)
	start := len(res) - 32 - 1
	end := len(res) - 16 - 1
	for i := 0; i < len(res); i++ {
		if i > start && i <= end {
			res[i] = byte(0)
		}
		if i > end {
			res[i] = res[i-end-1]
		}
	}
	_, err := userDataDecodeCBCWithChecks(res, iv, key)
	if err != nil {
		erStr := err.Error()
		chunks := strings.Split(erStr, " in message ")
		pt := []byte(chunks[1])
		frst := pt[0:16]
		scnd := pt[len(pt)-16 : len(pt)]
		iv := first.XOR(frst, scnd)
		fmt.Printf("the IV is: %q\n", iv)
	}
}

func Sha1mac(mes, key []byte) [20]byte {
	return sha1.Sum(append(key, mes...))
}
