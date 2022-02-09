package sixth

import (
	"log"
	"io"
	"fmt"
    "bytes"
	"math"
	"math/big"
	"errors"
	"io/ioutil"
	"strings"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/md5"
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

func RSAPad(pt []byte, padLen int) []byte {
    out := []byte{0x00, 0x01}
    padBts := make([]byte, padLen)
    for i := range padBts {
        padBts[i] = 0xff
    }
    out = append(out, padBts...)
    out = append(out, 0x00)
    out = append(out, pt...)
    return out
}

func RSASign(msg []byte, priv fifth.RSAPrivateKey) []byte {
    k := priv.N.BitLen() / 8
    hsh := md5.Sum(msg)
    pt, _ := asn1.Marshal(hsh[:])
    padLen := k - 3 - len(pt)
    padded := RSAPad(pt, padLen)
    hshInt := new(big.Int).SetBytes(padded)
	ct := fifth.ExpInt(hshInt, priv.D, priv.N)
    return ct.Bytes()
}

func RSAVerifySignature(msg []byte, sig []byte, pub fifth.RSAPublicKey) bool {
    // note: constant time comparisons should be used in real world applications
    // converting to int consumes leading 00h, do I have to add it on decryption?
    hshInt := new(big.Int).SetBytes(sig)
	dataInt := fifth.ExpInt(hshInt, pub.E, pub.N)
    data := dataInt.Bytes()
    if len(data) < 11 {
        return false
    }
    ptStart := -1
    if data[0] == 0x01 && data[1] == 0xff {
        for i := 2; i < len(data); i++ {
            if data[i] == 0 {
                ptStart = i+1
                break
            }
        }
    }
    if ptStart == -1 {
        return false
    }
    pt := data[ptStart:]
    sigHsh := []byte{}
    _, err := asn1.Unmarshal(pt, &sigHsh)
    if err != nil {
        return false
    }
    newHsh := md5.Sum(msg)
    res := bytes.Compare(sigHsh, newHsh[:])
    return res == 0
}

func RSAForgeSignature(msg []byte, pub fifth.RSAPublicKey) []byte {
    k := pub.N.BitLen() / 8
    hsh := md5.Sum(msg)
    pt, _ := asn1.Marshal(hsh[:])
    padded := RSAPad(pt, 1)
    zero := make([]byte, k-len(padded))
    padded = append(padded, zero...)
    fgInt := new(big.Int).SetBytes(padded)
    res, _ := fifth.BigCbrt(fgInt)
    return res.Bytes()
}

func FortySecond() {
	pub, priv := fifth.RSAGenKeys()
    msg := "hi mom"
    sig := RSASign([]byte(msg), priv)
    valid := RSAVerifySignature([]byte(msg), sig, pub)
    fmt.Printf("valid: %v\n", valid)

    forged := RSAForgeSignature([]byte(msg), pub)
    forgedValid := RSAVerifySignature([]byte(msg), forged, pub)
    fmt.Printf("forged signature accepted: %v\n", forgedValid)
}

type DSAPrivateKey struct {
	x *big.Int
    q *big.Int
    g *big.Int
    p *big.Int
}

type DSAPublicKey struct {
	y *big.Int
    q *big.Int
    g *big.Int
    p *big.Int
}

func DSAGenKeys() (DSAPublicKey, DSAPrivateKey) {
    p, _ := new(big.Int).SetString("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16)
    q, _ := new(big.Int).SetString("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)
    g, _ := new(big.Int).SetString("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16)

	x, _ := rand.Int(rand.Reader, new(big.Int).Sub(q, big.NewInt(2)))
    x.Add(x, big.NewInt(1))
    y := fifth.ExpInt(g, x, p)

    return DSAPublicKey{y: y, q: q, g: g, p: p}, DSAPrivateKey{x: x, q: q, g: g, p: p}
}

func DSAVerifySignature(msg []byte, pub DSAPublicKey, r *big.Int, s *big.Int) bool {
    w, err := fifth.ModInv(s, pub.q)
    if err != nil {
        panic("error")
    }
    hsh := sha1.Sum(msg)
    hshInt := new(big.Int).SetBytes(hsh[:])
    u1 := new(big.Int).Mul(hshInt, w)
    u1.Mod(u1, pub.q)
    u2 := new(big.Int).Mul(r, w)
    u2.Mod(u2, pub.q)

    gu := fifth.ExpInt(pub.g, u1, pub.p)
    yu := fifth.ExpInt(pub.y, u2, pub.p)
    v := new(big.Int).Mul(gu, yu)
    v.Mod(v, pub.p)
    v.Mod(v, pub.q)
    return v.Cmp(r) == 0
}

func testDSAImplementation(msg []byte) {
	pub, _ := DSAGenKeys()
    // verify that the algo works correctly by checking the signature
    pub.y.SetString("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17", 16)
    r, _ := new(big.Int).SetString("548099063082341131477253921760299949438196259240", 10)
    s, _ := new(big.Int).SetString("857042759984254168557880549501802188789837994940", 10)
    if !DSAVerifySignature(msg, pub, r, s){
        panic("Something is wrong with DSA implementation")
    }
}

func DSASign(msg []byte, priv DSAPrivateKey) (r, s *big.Int) {
    k, _ := rand.Int(rand.Reader, new(big.Int).Sub(priv.q, big.NewInt(2)))
    k.Add(k, big.NewInt(1))

    r = fifth.ExpInt(priv.g, k, priv.p)
    r.Mod(r, priv.q)

    if r.Cmp(big.NewInt(0)) != 0 {
        modK, _ := fifth.ModInv(k, priv.q)
        xr := new(big.Int).Mul(priv.x, r)
        hsh := sha1.Sum(msg)
        hshInt := new(big.Int).SetBytes(hsh[:])
        xrHsh := new(big.Int).Add(xr, hshInt)
        xrHsh.Mod(xrHsh, priv.q)
        s = new(big.Int).Mul(modK, xrHsh)
        s.Mod(s, priv.q)
        if s.Cmp(big.NewInt(0)) != 0 {
            return r, s
        }
    }
    return DSASign(msg, priv)
}

func DSARecoverPrivateKey(msg []byte, r, s, k, q *big.Int) *big.Int {
    hsh := sha1.Sum(msg)
    hshInt := new(big.Int).SetBytes(hsh[:])
    x := new(big.Int).Mul(s, k)
    x.Sub(x, hshInt)
    rInv, _ := fifth.ModInv(r, q)
    x.Mul(x, rInv)
    x.Mod(x, q)
    return x
}

func pickDSAK(msg []byte) (*big.Int, error) {
    hsh := "0954edd5e0afe5542a4adf012611a91912a3ec16"
    r, _ := new(big.Int).SetString("548099063082341131477253921760299949438196259240", 10)
    s, _ := new(big.Int).SetString("857042759984254168557880549501802188789837994940", 10)
    q, _ := new(big.Int).SetString("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)

    for i := 0; i <= math.MaxUint16; i++ {
        k := big.NewInt(int64(i))
        x := DSARecoverPrivateKey(msg, r, s, k, q)
        hx := x.Text(16)
        _hsh := sha1.Sum([]byte(hx))
        guess := hex.EncodeToString(_hsh[:])

        if guess == hsh {
            return x, nil
        }
    }
    return nil, errors.New("Haven't found anything")
}

func FortyThird() {
    msg := []byte("For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n")
    testDSAImplementation(msg)

	pub, priv := DSAGenKeys()
    r, s := DSASign(msg, priv)
    DSAVerifySignature(msg, pub, r, s)
    x, err := pickDSAK(msg)
    if err == nil {
        fmt.Printf("private key recovered: %v\n", x)
    }
}

type MsgDSASignature struct {
    msg string
    s *big.Int
    r *big.Int
}

func loadAndParseSigs() []MsgDSASignature {
    data, err := ioutil.ReadFile("44.txt")
	if err != nil {
		log.Fatal(err)
	}
    msgs := []MsgDSASignature{}
	msgStrs := strings.Split(string(data), "msg: ")
    for _, msg := range msgStrs[1:] {
        msgVals := strings.Split(msg, "\n")
        msgStrct := MsgDSASignature{msg: msgVals[0]}
        for i, msgKV := range msgVals[1:] {
            val := strings.Split(msgKV, ": ")
            if i == 0 {
                msgStrct.s, _ = new(big.Int).SetString(val[1], 10)
            } else if i == 1 {
                msgStrct.r, _ = new(big.Int).SetString(val[1], 10)
            } else if i == 2 {
                m, _ := new(big.Int).SetString(val[1], 16)
                hsh := sha1.Sum([]byte(msgStrct.msg))
                if bytes.Compare(hsh[:], m.Bytes()) != 0 {
                    log.Fatalf("Signature is broken for message: '%v'", msgStrct.msg)
                }
            }
        }
        //fmt.Printf("msg: %v, s: %v, r: %v\n", msgStrct.msg, msgStrct.s, msgStrct.r)
        msgs = append(msgs, msgStrct)
    }
    return msgs
}

func RecoverKFromMsgs(m1, m2, s1, s2, q *big.Int) (k *big.Int) {
    m1m2 := new(big.Int).Sub(m1, m2)
    m1m2.Mod(m1m2, q)
    s1s2 := new(big.Int).Sub(s1, s2)
    s1s2.Mod(s1s2, q)
    s1s2Inv, _ := fifth.ModInv(s1s2, q)
    k = new(big.Int).Mul(m1m2, s1s2Inv)
    return k
}

func FortyFourth() {
    privHsh := "ca8f6f7c66fa362d40760d135b763eb8527d3d52"
    q, _ := new(big.Int).SetString("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)
    sigs := loadAndParseSigs()
    var x *big.Int;
    for i, sig := range sigs {
        hsh := sha1.Sum([]byte(sig.msg))
        m1 := new(big.Int).SetBytes(hsh[:])
        for i2, sig2 := range sigs {
            if i == i2 {
                continue
            }
            hsh := sha1.Sum([]byte(sig2.msg))
            m2 := new(big.Int).SetBytes(hsh[:])

            k := RecoverKFromMsgs(m1, m2, sig.s, sig2.s, q)
            _x := DSARecoverPrivateKey([]byte(sig.msg), sig.r, sig.s, k, q)
            hx := _x.Text(16)
            _hsh := sha1.Sum([]byte(hx))
            guess := hex.EncodeToString(_hsh[:])

            if guess == privHsh {
                x = _x
                break
            }
        }
    }
    if x != nil {
        p, _ := new(big.Int).SetString("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16)
        g, _ := new(big.Int).SetString("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16)

        y := fifth.ExpInt(g, x, p)
        fmt.Printf("x: %v\n", x)
        fmt.Printf("y: %x\n", y)

    }
}

func DSAGenKeysWithParams(g *big.Int) (DSAPublicKey, DSAPrivateKey) {
    p, _ := new(big.Int).SetString("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16)
    q, _ := new(big.Int).SetString("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)

	x, _ := rand.Int(rand.Reader, new(big.Int).Sub(q, big.NewInt(2)))
    x.Add(x, big.NewInt(1))
    y := fifth.ExpInt(g, x, p)

    return DSAPublicKey{y: y, q: q, g: g, p: p}, DSAPrivateKey{x: x, q: q, g: g, p: p}
}

// g=0 case is not possible with the regular DSA signing algorithm
func DSASignRelaxed(msg []byte, priv DSAPrivateKey) (r, s *big.Int) {
    k, _ := rand.Int(rand.Reader, new(big.Int).Sub(priv.q, big.NewInt(2)))
    k.Add(k, big.NewInt(1))

    r = fifth.ExpInt(priv.g, k, priv.p)
    r.Mod(r, priv.q)

    modK, _ := fifth.ModInv(k, priv.q)
    xr := new(big.Int).Mul(priv.x, r)
    hsh := sha1.Sum(msg)
    hshInt := new(big.Int).SetBytes(hsh[:])
    xrHsh := new(big.Int).Add(xr, hshInt)
    xrHsh.Mod(xrHsh, priv.q)
    s = new(big.Int).Mul(modK, xrHsh)
    s.Mod(s, priv.q)
    return r, s
}

func DSAMagicSignature(pub DSAPublicKey, p, q *big.Int) (r, s *big.Int) {
    // not sure what z actually is, so just assume that it's a rand int
    z, _ := rand.Int(rand.Reader, new(big.Int).Sub(q, big.NewInt(2)))
    z.Add(z, big.NewInt(1))

    r = fifth.ExpInt(pub.y, z, p)
    r.Mod(r, q)
    zInv, _ := fifth.ModInv(z, q)
    s = new(big.Int).Mul(r, zInv)
    return
}

func FortyFifth() {
    msg := []byte("Hello, world")
    msg2 := []byte("Goodbye, world")

    p, _ := new(big.Int).SetString("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16)
    g0 := big.NewInt(0)
    g0pub, g0priv := DSAGenKeysWithParams(g0)
    g0pub2, g0priv2 := DSAGenKeysWithParams(g0)
    fmt.Printf("g=0 first keypair y=%v, x=%v\n", g0pub.y, g0priv.x)
    fmt.Printf("g=0 second keypaiy y=%v, x=%v\n", g0pub2.y, g0priv2.x)
    r, s := DSASignRelaxed(msg, g0priv)
    fmt.Printf("g=0 signature: r=%v s=%v\n", r, s)
    res := DSAVerifySignature(msg2, g0pub, r, s)
    fmt.Printf("g=0 sig for arbitrary message verified: %v\n", res)
    res1 := DSAVerifySignature(msg2, g0pub2, r, s)
    fmt.Printf("g=0 sig for arbitrary message and pubkey verified: %v\n", res1)

    g := p.Add(p, big.NewInt(1))
    pub, priv := DSAGenKeysWithParams(g)
    pub2, priv2 := DSAGenKeysWithParams(g)

    fmt.Printf("g=p+1 first keypair y=%v, x=%v\n", pub.y, priv.x)
    fmt.Printf("g=p+1 second keypaiy y=%v, x=%v\n", pub2.y, priv2.x)
    r1, s1 := DSASign(msg, priv)
    fmt.Printf("g=p+1 signature: r=%v s=%v\n", r1, s1)
    res2 := DSAVerifySignature(msg2, pub, r1, s1)
    fmt.Printf("g=p+1 sig for arbitrary message verified: %v\n", res2)

    res3 := DSAVerifySignature(msg2, pub2, r, s)
    fmt.Printf("g=p+1 sig for arbitrary message and pubkey failed: %v\n", res3 == false)

    r2, s2 := DSAMagicSignature(pub, pub.p, pub.q)
    fmt.Printf("g=p+1 magic sig: r=%v s=%v\n", r2, s2)
    res4 := DSAVerifySignature(msg, pub, r2, s2)
    fmt.Printf("g=p+1 magic sig for arbitrary message verified: %v\n", res4)
    res5 := DSAVerifySignature(msg2, pub, r2, s2)
    fmt.Printf("g=p+1 magic sig for arbitrary message verified: %v\n", res5)

    res6 := DSAVerifySignature(msg2, pub2, r2, s2)
    fmt.Printf("g=p+1 magic sig for arbitrary message and pubkey verified: %v\n", res6)
}

func isEven(pt *big.Int) bool {
    one := big.NewInt(1)
    res := new(big.Int).And(pt, one)
    return res.Cmp(one) != 0
}

var (pub, priv = fifth.RSAGenKeys())

func RSAParityOracle(ct *big.Int) bool {
	pt := fifth.RSADecrypt(priv, ct)
    return isEven(pt)
}

func bClone(a *big.Int) *big.Int {
    return new(big.Int).SetBytes(a.Bytes())
}

func DivByTwo(a *big.Int) *big.Int {
    mode := 0
    var res *big.Int
    if mode == 1 {
        res, _ = new(big.Int).DivMod(a, big.NewInt(2), new(big.Int))
    } else {
        res = new(big.Int).Div(a, big.NewInt(2))
    }
    return res
}

func decryptRSAViaOracle(ct *big.Int, pub fifth.RSAPublicKey) []byte {
    ptStart := big.NewInt(0)
    var N *big.Int
    nPrime := 1
    if nPrime == 1 {
        N = bClone(pub.N)
    } else {
        N = new(big.Int).Sub(pub.N, big.NewInt(1))
    }
    ptEnd := bClone(N)
    accumN := bClone(N)
    current := bClone(ct)
    two := big.NewInt(2)
    twoEnc := fifth.RSAEncrypt(pub, two)
    twos := big.NewInt(1)
    // log2(N) iterations
    for twos.Cmp(N) <= 0 {
        current.Mul(current, twoEnc)
        even := RSAParityOracle(current)
        accumN = DivByTwo(accumN)
        if even == true {
            ptEnd.Sub(ptEnd, accumN)
        } else {
            ptStart.Sub(ptStart, accumN)
        }
        twos.Mul(twos, two)
    }
    return ptEnd.Bytes()
}

func FortySixth() {
    secret := "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
	secretBt, _ := base64.StdEncoding.DecodeString(secret)
	secretPt := new(big.Int).SetBytes(secretBt)
	ct := fifth.RSAEncrypt(pub, secretPt)
    pt := decryptRSAViaOracle(ct, pub)
    fmt.Printf("%v\n", string(pt))
}