# VOPRF key generation

Generates a new (V)OPRF key for the secp256r1 curve, along with a public
commitment value `H` corresponding to `H = kG`, where `G` is the curves
generator. The commitment value is signed using a provided ECDSA signing
key.

## Quickstart

Generate (V)OPRF key and commitment file using a test ECDSA key:
```
go run main.go --ecdsa-key-path=testdata/test.ecdsa.key.pem
```

Generate ECDSA signing key (using openssl), and then generate signed (V)OPRF
data using that key:
```
openssl ecparam -name secp256r1 -genkey -out ecdsa.key.pem -noout
go run main.go --ecdsa-key-path=ecdsa.key.pem
```
