// Randomly samples a new OPRF key for the P-256 curve, and generates a
// commitment value H = kG along with an expiry date and an ECDSA signature

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"time"
)

type commitment struct {
	H      string    `json:"H"`
	Expiry time.Time `json:"expiry"`
	Sig    []byte    `json:"sig"`
}

func main() {
	var outKey, outCommitment, ecdsaKeyPath string
	commitmentFilename := fmt.Sprintf("commitment_%s.json", time.Now().Format(time.RFC3339))
	oprfKeyFilename := fmt.Sprintf("oprf_key_%s", time.Now().Format(time.RFC3339))
	flag.StringVar(&outKey, "oprf-key-file", oprfKeyFilename, "output path for the commitment")
	flag.StringVar(&outCommitment, "commitment-file", commitmentFilename, "output path for the OPRF key")
	flag.StringVar(&ecdsaKeyPath, "ecdsa-key-path", "", "path of ECDSA signing key")
	flag.Parse()

	if ecdsaKeyPath == "" {
		log.Println("Must specify ECDSA key file path")
		flag.Usage()
		return
	}

	ecdsaSigningKey, err := retrieveEcdsaKey(ecdsaKeyPath)
	if err != nil {
		log.Fatalln(err)
		return
	}

	// Get curve and hash from PEM
	keyCurve := ecdsaSigningKey.PublicKey.Curve
	if keyCurve != elliptic.P256() {
		log.Fatalln("ECDSA signing key should be for the secp256r1 curve")
	}

	// generate OPRF key k, and  H = kG
	oprfKeyBytes, x, y, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalln(err)
	}
	H := point{Curve: elliptic.P256(), X: x, Y: y}
	if !H.isOnCurve() {
		log.Fatalln("Generated commitment is corrupt")
	}

	// encode data for signing
	strH := base64.StdEncoding.EncodeToString(H.marshal())
	expiry := time.Now().AddDate(1, 0, 0)
	c := make(map[string]interface{})
	c["H"] = strH
	c["expiry"] = expiry

	// sign data
	dataToSign, err := json.Marshal(c)
	if err != nil {
		log.Fatalln(err)
	}
	sig, err := signCommitment(ecdsaSigningKey, dataToSign)
	if err != nil {
		log.Fatalln(err)
	}

	// construct commitment object
	newComm := commitment{
		H:      strH,
		Expiry: expiry,
		Sig:    sig,
	}
	commBytes, err := json.MarshalIndent(newComm, "", "    ")
	if err != nil {
		log.Fatalln(err)
	}

	// write files
	err = ioutil.WriteFile(outKey, oprfKeyBytes, os.FileMode(0644))
	if err != nil {
		log.Fatalln(err)
	}
	err = ioutil.WriteFile(outCommitment, commBytes, os.FileMode(0644))
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Printf("OPRF key file: %v\nCommitment file: %v\n", outKey, outCommitment)
	return
}

// signCommitments signs the "H" and "expiry" fields of the commitment and
// returns an asn1 encoded signature
func signCommitment(ecdsaKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	out := sha256.Sum256(data)
	hashed := out[:]
	r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, hashed)
	if err != nil {
		return nil, err
	}

	sig, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// retrieveEcdsaKey outputs the ECDSA signing key as bytes from either file or
// ENV.
func retrieveEcdsaKey(path string) (*ecdsa.PrivateKey, error) {
	// retrieve key from file if path is non-empty, or ENV otherwise
	pemBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(pemBytes)
	if len(rest) != 0 {
		return nil, errors.New("PEM block did not decode properly")
	}

	// retrieve actual key from PEM-encoded bytes
	var privKey *ecdsa.PrivateKey
	if block != nil {
		if block.Type == "EC PRIVATE KEY" {
			privKey, err = x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, errors.New("Key is not EC PRIVATE KEY, it is " + block.Type)
		}
	} else {
		return nil, errors.New("PEM block is nil")
	}

	return privKey, nil
}

type point struct {
	Curve elliptic.Curve
	X, Y  *big.Int
}

// isOnCurve checks that the point coordinates are valid for the given curve
func (p *point) isOnCurve() bool {
	return p.Curve.IsOnCurve(p.X, p.Y)
}

// marshal calls through to elliptic.Marshal using the Curve field of the
// receiving point. This produces an uncompressed marshaling as specified in
// SEC1 2.3.3.
func (p *point) marshal() []byte {
	return elliptic.Marshal(p.Curve, p.X, p.Y)
}
