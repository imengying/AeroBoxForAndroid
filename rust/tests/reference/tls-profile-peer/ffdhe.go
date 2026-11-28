package main

// This reference-only implementation uses Go math/big as an independent
// arithmetic oracle. It is variable-time and must never become production code.
import (
	"crypto/rand"
	"errors"
	"math/big"
)

func ffdheParameters(group uint16) (*big.Int, int, int, error) {
	var encoded string
	var width, secretBytes int
	switch group {
	case 256:
		encoded = "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f619172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa886b423861285c97ffffffffffffffff"
		width, secretBytes = 256, 32
	case 257:
		encoded = "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f619172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa886b4238611fcfdcde355b3b6519035bbc34f4def99c023861b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91caefe130985139270b4130c93bc437944f4fd4452e2d74dd364f2e21e71f54bff5cae82ab9c9df69ee86d2bc522363a0dabc521979b0deada1dbf9a42d5c4484e0abcd06bfa53ddef3c1b20ee3fd59d7c25e41d2b66c62e37ffffffffffffffff"
		width, secretBytes = 384, 48
	default:
		return nil, 0, 0, errors.New("unsupported FFDHE group")
	}
	prime, ok := new(big.Int).SetString(encoded, 16)
	if !ok {
		panic("invalid fixed RFC7919 modulus")
	}
	return prime, width, secretBytes, nil
}

func ffdheExchange(group uint16, public []byte) ([]byte, []byte, error) {
	_, _, size, err := ffdheParameters(group)
	if err != nil {
		return nil, nil, err
	}
	secret := make([]byte, size)
	if _, err = rand.Read(secret); err != nil {
		return nil, nil, err
	}
	defer clear(secret)
	secret[0] |= 128
	return ffdheWithSecret(group, public, secret)
}

func ffdheWithSecret(group uint16, public, secret []byte) ([]byte, []byte, error) {
	prime, width, size, err := ffdheParameters(group)
	if err != nil {
		return nil, nil, err
	}
	if len(public) != width || len(secret) != size || secret[0]&128 == 0 {
		return nil, nil, errors.New("invalid fixed-width FFDHE input")
	}
	one := big.NewInt(1)
	peer := new(big.Int).SetBytes(public)
	maximum := new(big.Int).Sub(prime, one)
	if peer.Cmp(one) <= 0 || peer.Cmp(maximum) >= 0 {
		return nil, nil, errors.New("FFDHE peer outside 1 < Y < p-1")
	}
	exponent := new(big.Int).SetBytes(secret)
	server := new(big.Int).Exp(big.NewInt(2), exponent, prime)
	shared := new(big.Int).Exp(peer, exponent, prime)
	return server.FillBytes(make([]byte, width)), shared.FillBytes(make([]byte, width)), nil
}
