package sixth

import (
	"log"
	"io"
	"fmt"
	"math"
	"math/big"
	"encoding/base64"
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"net/url"
	"knivets.com/cryptopals/fifth"
)

func buildUrl(msg string) string {
	u, err := url.Parse("http://localhost:9000/test")
	if err != nil {
		log.Fatal(err)
	}
	q := u.Query()
	q.Set("message", msg)
	u.RawQuery = q.Encode()
	return u.String()
}

func RSADecryptionServer(priv fifth.RSAPrivateKey) {
    state := map[string]bool{}
	http.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		args := r.URL.Query()
		msg := args["message"]
		if len(msg) > 0 {
            res, ok := base64.StdEncoding.DecodeString(msg[0])
            if ok != nil {
                return
            }

            hash := sha256.Sum256(res)
            hash_str := string(hash[:])
            if state[hash_str] {
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            state[hash_str] = true

            ct := new(big.Int).SetBytes(res)
            pt := fifth.RSADecrypt(priv, ct)
            w.WriteHeader(http.StatusOK)
            fmt.Fprintf(w, string(pt.Bytes()))
		} else {
            w.WriteHeader(http.StatusBadRequest)
        }
	})

	log.Fatal(http.ListenAndServe(":9000", nil))
}

func RSAMessageRecoveryClient(msg string) (string, bool) {
    url := buildUrl(msg)

	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
        respBody, _ := io.ReadAll(resp.Body)
        return string(respBody), true
	}
    return "", false
}

func interceptSecretMsg(pub fifth.RSAPublicKey) string {
    val := "{ time: 1356304276, social: '555-55-5555', }"
	pt := new(big.Int).SetBytes([]byte(val))
	ct := fifth.RSAEncrypt(pub, pt)

    return string(base64.StdEncoding.EncodeToString(ct.Bytes()))
}

func forgeMsg(msg string, pub fifth.RSAPublicKey) (string, *big.Int) {
    ct, _ := base64.StdEncoding.DecodeString(msg)
    ctInt := new(big.Int).SetBytes(ct)
    n := pub.N
    e := pub.E
	_s, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
    s := fifth.BigMod(_s, n)
    res := fifth.BigMod(fifth.BigMul(fifth.ExpInt(s, e, n), ctInt), n)
    return string(base64.StdEncoding.EncodeToString(res.Bytes())), s
}

func cleanUpForgedPT(pt string, s *big.Int, pub fifth.RSAPublicKey) string {
    ptBt := []byte(pt)
    p := new(big.Int).SetBytes(ptBt)
    mdInv, ok := fifth.ModInv(s, pub.N)
    if ok != nil {
        log.Fatalf("couldn't find modinv")
    }
    res := fifth.BigMod(fifth.BigMul(p, mdInv), pub.N).Bytes()
    return string(res)
}

func FortyFirst() {
	pub, priv := fifth.RSAGenKeys()
	go RSADecryptionServer(priv)

    encryptedMsg := interceptSecretMsg(pub)

    _, firstRes := RSAMessageRecoveryClient(encryptedMsg)
    if !firstRes {
        log.Fatalf("first decrypt of a cyphertext should work")
    }

    _, secondRes := RSAMessageRecoveryClient(encryptedMsg)
    if secondRes {
        log.Fatalf("second decrypt of the same cyphertext should fail")
    }

    forgedMsg, s := forgeMsg(encryptedMsg, pub)
    pt2, _ := RSAMessageRecoveryClient(forgedMsg)
    cleanPt := cleanUpForgedPT(pt2, s, pub)

    fmt.Printf("forged cyphertext is decrypted regadless of invocation number: %v\n", cleanPt)
}
