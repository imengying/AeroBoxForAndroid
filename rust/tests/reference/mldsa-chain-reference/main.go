// Generate independent, disposable PKI fixtures using Go 1.27's ML-DSA.
// This module and every generated private key are reference-test inputs only.
package main

import (
    "crypto"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/mldsa"
    "crypto/rand"
    "crypto/sha256"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/asn1"
    "encoding/hex"
    "encoding/json"
    "encoding/pem"
    "flag"
    "fmt"
    "math/big"
    "os"
    "path/filepath"
    "runtime"
    "time"
)

type identity struct {
    cert *x509.Certificate
    key crypto.Signer
    der []byte
}

func must[T any](value T, err error) T {
    if err != nil { panic(err) }
    return value
}

var serial int64
func issue(name string, key crypto.Signer, parent *identity, ca bool, usage x509.ExtKeyUsage) identity {
    serial++
    template := &x509.Certificate{
        SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
        NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
        NotAfter: time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
        BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature,
    }
    if ca {
        template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
        template.MaxPathLen = 2
    } else {
        template.DNSNames = []string{"mldsa.aerobox.test"}
        template.ExtKeyUsage = []x509.ExtKeyUsage{usage}
    }
    issuer, signer := template, key
    if parent != nil { issuer, signer = parent.cert, parent.key }
    der := must(x509.CreateCertificate(rand.Reader, template, issuer, key.Public(), signer))
    return identity{cert: must(x509.ParseCertificate(der)), key: key, der: der}
}

func write(path string, data []byte) {
    if err := os.WriteFile(path, data, 0600); err != nil { panic(err) }
}

func save(directory, name string, value identity) {
    write(filepath.Join(directory, name+".der"), value.der)
    write(filepath.Join(directory, name+".pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: value.der}))
}

type encodedCertificate struct {
    TBS asn1.RawValue
    Algorithm pkix.AlgorithmIdentifier
    Signature asn1.BitString
}

func signedNullAlgorithm(value identity, issuer crypto.Signer, mode string) []byte {
    var encoded encodedCertificate
    rest, err := asn1.Unmarshal(value.der, &encoded)
    if err != nil || len(rest) != 0 { panic("bad original certificate encoding") }
    var fields []asn1.RawValue
    for rest = encoded.TBS.Bytes; len(rest) != 0; {
        var field asn1.RawValue
        rest, err = asn1.Unmarshal(rest, &field)
        if err != nil { panic(err) }; fields = append(fields, field)
    }
    if len(fields) < 7 || fields[0].Class != 2 || fields[0].Tag != 0 { panic("unexpected v3 TBS layout") }
    switch mode {
    case "signature-null":
        if _, ok := issuer.(*mldsa.PrivateKey); !ok { panic("requires ML-DSA issuer") }
        encoded.Algorithm.Parameters = asn1.RawValue{Tag: 5}
        fields[2] = asn1.RawValue{FullBytes: must(asn1.Marshal(encoded.Algorithm))}
    case "spki-null":
        if _, ok := value.key.(*mldsa.PrivateKey); !ok { panic("requires ML-DSA leaf") }
        var public struct { Algorithm pkix.AlgorithmIdentifier; Key asn1.BitString }
        rest, err = asn1.Unmarshal(fields[6].FullBytes, &public)
        if err != nil || len(rest) != 0 { panic("bad original SPKI encoding") }
        public.Algorithm.Parameters = asn1.RawValue{Tag: 5}
        fields[6] = asn1.RawValue{FullBytes: must(asn1.Marshal(public))}
    default: panic("unsupported mutation")
    }
    var contents []byte
    for _, field := range fields { contents = append(contents, field.FullBytes...) }
    tbs := must(asn1.Marshal(asn1.RawValue{Tag: 16, IsCompound: true, Bytes: contents}))
    encoded.TBS = asn1.RawValue{FullBytes: tbs}
    var signature []byte
    switch key := issuer.(type) {
    case *mldsa.PrivateKey:
        signature = must(key.Sign(rand.Reader, tbs, crypto.Hash(0)))
        if err := mldsa.Verify(key.PublicKey(), tbs, signature, nil); err != nil { panic(err) }
    case *ecdsa.PrivateKey:
        digest := sha256.Sum256(tbs)
        signature = must(key.Sign(rand.Reader, digest[:], crypto.SHA256))
        if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], signature) { panic("mutation lost valid issuer signature") }
    default: panic("unsupported issuer")
    }
    encoded.Signature = asn1.BitString{Bytes: signature, BitLength: len(signature)*8}
    return must(asn1.Marshal(encoded))
}

func main() {
    output := flag.String("output", "", "new output directory")
    flag.Parse()
    if *output == "" || flag.NArg() != 0 { panic("-output is required") }
    if err := os.Mkdir(*output, 0700); err != nil { panic(err) }
    var cases []map[string]any
    for _, parameter := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
        pq := func() crypto.Signer { return must(mldsa.GenerateKey(parameter)) }
        ec := func() crypto.Signer { return must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)) }
        for _, kind := range []string{"classical-ca-pq-leaf", "pq-ca-classical-leaf", "pq-chain"} {
            name := parameter.String()+"-"+kind
            directory := filepath.Join(*output, name)
            if err := os.Mkdir(directory, 0700); err != nil { panic(err) }
            rootKey, intermediateKey, leafKey := pq(), pq(), pq()
            switch kind {
            case "classical-ca-pq-leaf": rootKey, intermediateKey = ec(), ec()
            case "pq-ca-classical-leaf": intermediateKey, leafKey = ec(), ec()
            }
            root := issue(name+" root", rootKey, nil, true, 0)
            intermediate := issue(name+" intermediate", intermediateKey, &root, true, 0)
            leaf := issue("mldsa.aerobox.test", leafKey, &intermediate, false, x509.ExtKeyUsageServerAuth)
            wrongUsage := issue("mldsa.aerobox.test", leafKey, &intermediate, false, x509.ExtKeyUsageClientAuth)
            roots, chain := x509.NewCertPool(), x509.NewCertPool()
            roots.AddCert(root.cert); chain.AddCert(intermediate.cert)
            options := x509.VerifyOptions{Roots: roots, Intermediates: chain,
                DNSName: "mldsa.aerobox.test", CurrentTime: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}
            if _, err := leaf.cert.Verify(options); err != nil { panic(err) }
            if _, err := wrongUsage.cert.Verify(options); err == nil { panic("client-only EKU unexpectedly accepted") }
            save(directory, "root", root); save(directory, "intermediate", intermediate)
            save(directory, "leaf", leaf); save(directory, "client-only", wrongUsage)
            if _, ok := intermediate.key.(*mldsa.PrivateKey); ok {
                write(filepath.Join(directory, "signature-null.der"), signedNullAlgorithm(leaf, intermediate.key, "signature-null"))
            }
            if key, ok := leaf.key.(*mldsa.PrivateKey); ok {
                write(filepath.Join(directory, "spki-null.der"), signedNullAlgorithm(leaf, intermediate.key, "spki-null"))
                message := make([]byte, 64)
                for i := range message { message[i] = 0x20 }
                message = append(message, []byte("TLS 1.3, server CertificateVerify")...)
                message = append(message, 0)
                transcript := sha256.Sum256([]byte("independent AeroBox reference transcript"))
                message = append(message, transcript[:]...)
                signature := must(key.Sign(rand.Reader, message, crypto.Hash(0)))
                if err := mldsa.Verify(key.PublicKey(), message, signature, nil); err != nil { panic(err) }
                write(filepath.Join(directory, "cv-message.bin"), message)
                write(filepath.Join(directory, "cv-signature.bin"), signature)
            }
            private := must(x509.MarshalPKCS8PrivateKey(leaf.key))
            write(filepath.Join(directory, "leaf-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
            spki := must(x509.MarshalPKIXPublicKey(leaf.key.Public()))
            write(filepath.Join(directory, "leaf-spki.der"), spki)
            cases = append(cases, map[string]any{"name": name, "parameters": parameter.String(),
                "kind": kind, "leaf_public_key_algorithm": leaf.cert.PublicKeyAlgorithm.String(),
                "leaf_issuer_signature": leaf.cert.SignatureAlgorithm.String(),
                "intermediate_issuer_signature": intermediate.cert.SignatureAlgorithm.String()})
        }
    }
    files := make(map[string]string)
    err := filepath.WalkDir(*output, func(path string, entry os.DirEntry, err error) error {
        if err != nil { return err }
        if entry.IsDir() { return nil }
        data := must(os.ReadFile(path)); sum := sha256.Sum256(data)
        files[must(filepath.Rel(*output, path))] = hex.EncodeToString(sum[:])
        return nil
    })
    if err != nil { panic(err) }
    result := map[string]any{"scope": "independent Go certificate generation; no product or live TLS claim",
        "go_version": runtime.Version(), "cases": cases, "files": files,
        "validation_time_unix": time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC).Unix()}
    data := must(json.MarshalIndent(result, "", "  "))
    write(filepath.Join(*output, "manifest.json"), append(data, '\n'))
    fmt.Printf("Generated %d independently verified chains and %d wrong-EKU leaves\n", len(cases), len(cases))
}
