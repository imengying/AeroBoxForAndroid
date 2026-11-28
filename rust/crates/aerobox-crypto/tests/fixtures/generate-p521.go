// Run manually with Go's standard library to regenerate public test credentials
// and independently generated P-521 signatures. Not part of any product build.
//go:build ignore

package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
    "crypto/sha512"
    "crypto/x509"
    "crypto/x509/pkix"
    "math/big"
    "os"
    "time"
)

func write(name string, bytes []byte, err error) {
    if err != nil { panic(err) }
    if err := os.WriteFile(name, bytes, 0644); err != nil { panic(err) }
}
func main() {
    key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
    if err != nil { panic(err) }
    ca := &x509.Certificate{SerialNumber:big.NewInt(521), Subject:pkix.Name{CommonName:"AeroBox P-521 test root"},
        NotBefore:time.Date(2026,11,1,0,0,0,0,time.UTC), NotAfter:time.Date(2126,11,1,0,0,0,0,time.UTC),
        IsCA:true, BasicConstraintsValid:true, KeyUsage:x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
        SignatureAlgorithm:x509.ECDSAWithSHA512}
    cert, err := x509.CreateCertificate(rand.Reader,ca,ca,&key.PublicKey,key); write("p521-ca.der",cert,err)
    leaf := *ca
    leaf.SerialNumber=big.NewInt(522); leaf.Subject.CommonName="localhost"; leaf.IsCA=false
    leaf.DNSNames=[]string{"localhost"}; leaf.KeyUsage=x509.KeyUsageDigitalSignature
    leaf.ExtKeyUsage=[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
    for index, algorithm := range []x509.SignatureAlgorithm{x509.ECDSAWithSHA256,x509.ECDSAWithSHA384,x509.ECDSAWithSHA512} {
        leaf.SignatureAlgorithm=algorithm
        cert, err = x509.CreateCertificate(rand.Reader,&leaf,ca,&key.PublicKey,key)
        write([]string{"p521-cert-sha256.der","p521-cert-sha384.der","p521-cert.der"}[index],cert,err)
    }
    bytes, err := x509.MarshalPKCS8PrivateKey(key); write("p521-key.der",bytes,err)
    bytes, err = x509.MarshalECPrivateKey(key); write("p521-key-sec1.der",bytes,err)
    write("p521-public.sec1",elliptic.Marshal(elliptic.P521(),key.X,key.Y),nil)
    message := []byte("AeroBox independent Go P-521 fixture")
    sha256Digest := sha256.Sum256(message); sha384Digest := sha512.Sum384(message); sha512Digest := sha512.Sum512(message)
    for index, digest := range [][]byte{sha256Digest[:],sha384Digest[:],sha512Digest[:]} {
        signature, err := ecdsa.SignASN1(rand.Reader,key,digest)
        write([]string{"p521-signature-sha256.der","p521-signature-sha384.der","p521-signature-sha512.der"}[index],signature,err)
    }
    peer, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
    if err != nil { panic(err) }
    peerPublic, err := peer.PublicKey.ECDH(); if err != nil { panic(err) }
    local, err := key.ECDH(); if err != nil { panic(err) }
    secret, err := local.ECDH(peerPublic); write("p521-ecdh-secret.bin",secret,err)
    write("p521-ecdh-peer.sec1",peerPublic.Bytes(),nil)
}
