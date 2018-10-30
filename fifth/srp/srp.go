package srp

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"net/http"
	"net/url"
)

var N *big.Int
var g *big.Int = big.NewInt(2)
var k *big.Int = big.NewInt(3)
var I string = "test@example.com"
var P string = "secret"

func init() {
	NSlice, _ := hex.DecodeString(
		`ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff`)
	N = new(big.Int).SetBytes(NSlice)
}

func GenRandomInt64(num int64) int64 {
	res, _ := rand.Int(rand.Reader, big.NewInt(num))
	return res.Int64()
}

func GenRandomInt(num int64) *big.Int {
	res, _ := rand.Int(rand.Reader, big.NewInt(num))
	return res
}

func int64ToBytes(num int64) []byte {
	buff := new(bytes.Buffer)
	_ = binary.Write(buff, binary.LittleEndian, num)
	return buff.Bytes()
}

func bytesToInt64(data []byte) int64 {
	var res int64
	buff := bytes.NewReader(data)
	_ = binary.Read(buff, binary.LittleEndian, &res)
	return res
}

func ExpInt(a, b, p *big.Int) *big.Int {
	c := new(big.Int).Exp(a, b, p)
	return c
}

func HMACSHA256(message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	res := mac.Sum(nil)
	return res
}

func CheckMAC(message, messageMAC, key []byte) bool {
	expectedMAC := HMACSHA256(message, key)
	return hmac.Equal(messageMAC, expectedMAC)
}

var address string = "http://localhost:9000/"

func server() {
	salt := GenRandomInt64(math.MaxInt64)
	saltBt := int64ToBytes(salt)
	xH := sha256.Sum256(append(saltBt, []byte(P)...))
	x := new(big.Int).SetBytes(xH[:])
	v := ExpInt(g, x, N)
	var K []byte
	savedI := ""
	savedA := ""
	http.HandleFunc("/first", func(w http.ResponseWriter, r *http.Request) {
		status := http.StatusBadRequest
		if r.Method != "POST" {
			w.WriteHeader(status)
		}
		err := r.ParseForm()
		if err != nil {
			panic(err)
		}
		params := r.Form
		savedI = params.Get("I")
		savedA = params.Get("A")
		A, _ := new(big.Int).SetString(savedA, 16)
		b := GenRandomInt(math.MaxInt64)
		b.Mod(b, N)
		inB := ExpInt(g, b, N)
		kv := big.NewInt(0)
		kv.Mul(k, v)
		B := kv.Add(kv, inB)
		uH := sha256.Sum256(append(A.Bytes(), B.Bytes()...))
		u := new(big.Int).SetBytes(uH[:])
		vu := ExpInt(v, u, N)
		vu.Mul(A, vu)
		S := ExpInt(vu, b, N)
		Ktmp := sha256.Sum256(S.Bytes())
		K = Ktmp[:]
		w.WriteHeader(status)
		fmt.Fprintf(w, url.Values{
			"salt": {hex.EncodeToString(saltBt)}, "B": {B.Text(16)}}.Encode())
	})

	http.HandleFunc("/second", func(w http.ResponseWriter, r *http.Request) {
		status := http.StatusBadRequest
		if r.Method != "POST" {
			w.WriteHeader(status)
		}
		err := r.ParseForm()
		if err != nil {
			panic(err)
		}
		params := r.Form
		macSt := params.Get("mac")
		mac, _ := hex.DecodeString(macSt)
		res := CheckMAC(saltBt, mac, K)
		if res {
			fmt.Fprintf(w, "OK")
		} else {
			fmt.Fprintf(w, "ERROR")
		}
	})

	log.Fatal(http.ListenAndServe(":9000", nil))
}

func client() {
	a := GenRandomInt(math.MaxInt64)
	a.Mod(a, N)
	A := ExpInt(g, a, N)
	postData := url.Values{"I": {I}, "A": {A.Text(16)}}
	resp, err := http.PostForm(address+"first", postData)
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	bodyString := string(bodyBytes)
	data, _ := url.ParseQuery(bodyString)
	resp.Body.Close()
	B, _ := new(big.Int).SetString(data.Get("B"), 16)
	uH := sha256.Sum256(append(A.Bytes(), B.Bytes()...))
	u := new(big.Int).SetBytes(uH[:])
	saltBt, _ := hex.DecodeString(data.Get("salt"))
	xH := sha256.Sum256(append(saltBt, []byte(P)...))
	x := new(big.Int).SetBytes(xH[:])
	gx := ExpInt(g, x, N)
	kgx := gx.Mul(gx, k)
	lft := big.NewInt(0)
	lft.Sub(B, kgx)
	ux := big.NewInt(0)
	ux.Mul(u, x)
	rgt := big.NewInt(0)
	rgt.Add(a, ux)
	S := ExpInt(lft, rgt, N)
	K := sha256.Sum256(S.Bytes())
	hm := HMACSHA256(saltBt, K[:])
	macSt := hex.EncodeToString(hm)
	resp2, err2 := http.PostForm(address+"second", url.Values{
		"mac": {macSt}})
	if err2 != nil {
		fmt.Printf("%s\n", err)
		return
	}
	bodyBytes, _ = ioutil.ReadAll(resp2.Body)
	bodyString = string(bodyBytes)
	fmt.Printf("%s\n", bodyString)
}

func clientWithDynamicA(A *big.Int) {
	a := GenRandomInt(math.MaxInt64)
	a.Mod(a, N)
	postData := url.Values{"I": {I}, "A": {A.Text(16)}}
	resp, err := http.PostForm(address+"first", postData)
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	bodyString := string(bodyBytes)
	data, _ := url.ParseQuery(bodyString)
	resp.Body.Close()
	B, _ := new(big.Int).SetString(data.Get("B"), 16)
	uH := sha256.Sum256(append(A.Bytes(), B.Bytes()...))
	u := new(big.Int).SetBytes(uH[:])
	saltBt, _ := hex.DecodeString(data.Get("salt"))
	xH := sha256.Sum256(append(saltBt, []byte(P)...))
	x := new(big.Int).SetBytes(xH[:])
	gx := ExpInt(g, x, N)
	kgx := gx.Mul(gx, k)
	lft := big.NewInt(0)
	lft.Sub(B, kgx)
	ux := big.NewInt(0)
	ux.Mul(u, x)
	rgt := big.NewInt(0)
	rgt.Add(a, ux)
	S := ExpInt(lft, rgt, N)
	S = big.NewInt(0)
	K := sha256.Sum256(S.Bytes())
	hm := HMACSHA256(saltBt, K[:])
	macSt := hex.EncodeToString(hm)
	resp2, err2 := http.PostForm(address+"second", url.Values{
		"mac": {macSt}})
	if err2 != nil {
		fmt.Printf("%s\n", err)
		return
	}
	bodyBytes, _ = ioutil.ReadAll(resp2.Body)
	bodyString = string(bodyBytes)
	fmt.Printf("%s\n", bodyString)
}

func Srp() {
	go server()
	client()
}

func SrpZeroA() {
	go server()
	clientWithDynamicA(big.NewInt(0))
}

func SrpNA() {
	go server()
	clientWithDynamicA(N)
}

func SrpNA2() {
	go server()
	clientWithDynamicA(ExpInt(N, big.NewInt(2), big.NewInt(0)))
}
