package fourth

import (
	"cryptopals/first"
	"cryptopals/md4"
	"cryptopals/second"
	"cryptopals/sha1"
	"cryptopals/third"
	"fmt"
	"reflect"
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

func genSHA1Padding(ln uint64) []byte {
	res := []byte{}
	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64]byte
	tmp[0] = 0x80
	if ln%64 < 56 {
		res = append(res, tmp[0:56-ln%64]...)
	} else {
		//d.Write(tmp[0 : 64+56-len%64])
		res = append(res, tmp[0:64+56-ln%64]...)
	}

	// Length in bits.
	ln <<= 3
	sha1.PutUint64(tmp[:], ln)
	res = append(res, tmp[0:8]...)
	return res
}

var MacSecret []byte = []byte("secret")

func verifySHA1MAC(msg, sign []byte) bool {
	mac := Sha1mac(msg, MacSecret)
	return reflect.DeepEqual(mac[:], sign)
}

func getPrevBlockSize(ln uint64) uint64 {
	// rounding to the nearest 64 because the rest of the space
	// will be filled with padding up until 512 bits
	// adding 8 because 56+8 = 64, at which point we need to round
	// because 55 bytes is the last length which allows us to fit
	// the message into 512 block (55*8+8=448), which leaves space
	// only for the 64 bit message length
	return (ln + 64 + 8) &^ (64 - 1)
}

func ForgeSHA1(msg, orig, ext []byte) ([]byte, []byte) {
	h := [5]uint32{}
	_, h[0] = sha1.ConsumeUint32(orig[0:4])
	_, h[1] = sha1.ConsumeUint32(orig[4:8])
	_, h[2] = sha1.ConsumeUint32(orig[8:12])
	_, h[3] = sha1.ConsumeUint32(orig[12:16])
	_, h[4] = sha1.ConsumeUint32(orig[16:20])
	var forgedMsg []byte
	var forged [20]byte
	maxKeySize := 200
	for i := 0; i < maxKeySize; i++ {
		potLen := uint64(len(msg) + i)
		padGuess := genSHA1Padding(potLen)
		payload := append(padGuess, ext...)
		forgedMsg = append(msg, payload...)
		finLen := getPrevBlockSize(potLen)

		forged = sha1.CustomSHA1(h, ext, finLen)

		if verifySHA1MAC(forgedMsg, forged[:]) {
			return forgedMsg, forged[:]
		}
	}
	return []byte{}, []byte{}
}

func MD4Mac(mes, key []byte) []byte {
	return md4.Sum(append(key, mes...))
}

func verifyMD4MAC(msg, sign []byte) bool {
	mac := MD4Mac(msg, MacSecret)
	return reflect.DeepEqual(mac, sign)
}

func ForgeMD4(msg, orig, ext []byte) ([]byte, []byte) {
	h := [4]uint32{}
	_, h[0] = sha1.ConsumeUint32(orig[0:4])
	_, h[1] = sha1.ConsumeUint32(orig[4:8])
	_, h[2] = sha1.ConsumeUint32(orig[8:12])
	_, h[3] = sha1.ConsumeUint32(orig[12:16])
	var forgedMsg []byte
	var forged []byte
	maxKeySize := 64
	for i := 0; i < maxKeySize; i++ {
		potLen := uint64(len(msg) + i)
		padGuess := genSHA1Padding(potLen)
		payload := append(padGuess, ext...)
		forgedMsg = append(msg, payload...)
		finLen := getPrevBlockSize(potLen)

		forged = md4.CustomMD4(h, ext, finLen)

		if verifyMD4MAC(forgedMsg, forged) {
			return forgedMsg, forged
		}
	}
	return []byte{}, []byte{}
}
