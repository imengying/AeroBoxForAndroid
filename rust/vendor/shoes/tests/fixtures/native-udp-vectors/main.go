// Independent fixture generator for SIP004/007 and SIP022/023. This program is
// test tooling only; the Android library does not contain or invoke Go.
package main

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "crypto/hmac"
    "crypto/md5"
    "crypto/sha1"
    "encoding/base64"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "os"
    "golang.org/x/crypto/chacha20poly1305"
    "lukechampine.com/blake3"
)

const timestamp uint64 = 1700000000
var address = []byte{1, 1, 2, 3, 4, 1, 187}
var payload = []byte("udp-vector")
var clientID = []byte{1,2,3,4,5,6,7,8}
var serverID = []byte{17,18,19,20,21,22,23,24}

func must(err error) { if err != nil { panic(err) } }
func gcm(key []byte) cipher.AEAD { block,err := aes.NewCipher(key); must(err); aead,err:=cipher.NewGCM(block); must(err); return aead }
func u64(v uint64) []byte { result:=make([]byte,8); binary.BigEndian.PutUint64(result,v); return result }
func encryptBlock(key, in []byte) []byte { result:=make([]byte,16); block,err:=aes.NewCipher(key); must(err); block.Encrypt(result,in); return result }
func sessionKey(key,id []byte) []byte { out:=make([]byte,len(key)); blake3.DeriveKey(out,"shadowsocks 2022 session subkey",append(append([]byte{},key...),id...)); return out }
func legacyKey(size int) []byte {
    var out,previous []byte
    for len(out)<size { h:=md5.New(); h.Write(previous); h.Write([]byte("password")); previous=h.Sum(nil); out=append(out,previous...) }
    return out[:size]
}
func subkey(key,salt []byte,size int) []byte {
    extract:=hmac.New(sha1.New,salt); extract.Write(key); secret:=extract.Sum(nil)
    var out,previous []byte
    for count:=byte(1);len(out)<size;count++ { h:=hmac.New(sha1.New,secret); h.Write(previous); h.Write([]byte("ss-subkey")); h.Write([]byte{count}); previous=h.Sum(nil); out=append(out,previous...) }
    return out[:size]
}

func packet2022(key []byte, identities [][]byte, chacha, response bool, client []byte, number, stamp uint64, badType bool, badPadding bool) []byte {
    id:=clientID; kind:=byte(0)
    if response { id=serverID; kind=1 }
    if badType { kind=0 }
    separate:=append(append([]byte{},id...),u64(number)...)
    body:=append([]byte{kind},u64(stamp)...)
    if response { body=append(body,client...) }
    if badPadding { body=append(body,255,255) } else { body=append(body,0,0) }
    body=append(body,address...); body=append(body,payload...)
    if chacha {
        nonce:=bytes.Repeat([]byte{0x44},24); aead,err:=chacha20poly1305.NewX(key); must(err)
        return append(nonce,aead.Seal(nil,nonce,append(separate,body...),nil)...)
    }
    headerKey:=key
    if !response && len(identities)>0 { headerKey=identities[0] }
    output:=encryptBlock(headerKey,separate)
    if !response {
        keys:=append(append([][]byte{},identities...),key)
        for i:=0;i<len(identities);i++ { hash:=blake3.Sum256(keys[i+1]); block:=make([]byte,16); for j:=range block { block[j]=hash[j]^separate[j] }; output=append(output,encryptBlock(keys[i],block)...) }
    }
    return append(output,gcm(sessionKey(key,id)).Seal(nil,separate[4:],body,nil)...)
}

func main() {
    var vectors []map[string]any
    for _,name:=range []string{"aes-128-gcm","aes-256-gcm","chacha20-ietf-poly1305","2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305","2022-blake3-aes-128-gcm-eih","2022-blake3-aes-256-gcm-eih"} {
        size:=32; if name=="aes-128-gcm" || name=="2022-blake3-aes-128-gcm" || name=="2022-blake3-aes-128-gcm-eih" {size=16}
        modern:=bytes.HasPrefix([]byte(name),[]byte("2022")); chacha:=bytes.Contains([]byte(name),[]byte("chacha")); identities:=[][]byte(nil)
        key:=bytes.Repeat([]byte{0x33},size); password:="password"; method:=name
        var request,response []byte
        vector:=map[string]any{}
        if modern {
            password=base64.StdEncoding.EncodeToString(key)
            if bytes.HasSuffix([]byte(name),[]byte("-eih")) { identities=[][]byte{bytes.Repeat([]byte{0x11},size),bytes.Repeat([]byte{0x22},size)}; password=base64.StdEncoding.EncodeToString(identities[0])+":"+base64.StdEncoding.EncodeToString(identities[1])+":"+password; method=name[:len(name)-4] }
            request=packet2022(key,identities,chacha,false,clientID,0,timestamp,false,false)
            response=packet2022(key,nil,chacha,true,clientID,10,timestamp,false,false)
            vector["wrong_client"]=hex.EncodeToString(packet2022(key,nil,chacha,true,bytes.Repeat([]byte{0x88},8),10,timestamp,false,false))
            vector["old_time"]=hex.EncodeToString(packet2022(key,nil,chacha,true,clientID,10,timestamp-31,false,false))
            vector["future_time"]=hex.EncodeToString(packet2022(key,nil,chacha,true,clientID,10,timestamp+31,false,false))
            vector["wrong_type"]=hex.EncodeToString(packet2022(key,nil,chacha,true,clientID,10,timestamp,true,false))
            vector["bad_padding"]=hex.EncodeToString(packet2022(key,nil,chacha,true,clientID,10,timestamp,false,true))
            vector["late_packet"]=hex.EncodeToString(packet2022(key,nil,chacha,true,clientID,9,timestamp,false,false))
        } else {
            salt:=bytes.Repeat([]byte{0x44},size); key:=subkey(legacyKey(size),salt,size); aead:=gcm(key)
            if chacha { var err error; aead,err=chacha20poly1305.New(key); must(err) }
            request=append(salt,aead.Seal(nil,make([]byte,12),append(append([]byte{},address...),payload...),nil)...)
            salt=bytes.Repeat([]byte{0x55},size); key=subkey(legacyKey(size),salt,size); aead=gcm(key)
            if chacha { var err error; aead,err=chacha20poly1305.New(key); must(err) }
            response=append(salt,aead.Seal(nil,make([]byte,12),append(append([]byte{},address...),payload...),nil)...)
        }
        vector["method"]=method; vector["password"]=password; vector["request"]=hex.EncodeToString(request); vector["response"]=hex.EncodeToString(response)
        vectors=append(vectors,vector)
    }
    encoder:=json.NewEncoder(os.Stdout); encoder.SetIndent("","  "); must(encoder.Encode(vectors))
}
