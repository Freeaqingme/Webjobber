package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"hash"
	"math"
	"sync"
)

var (
	authkeySecret = []byte("phu8sae0Reih8vohngohjaix8zaeshei1Oochaideiz7jieti1ahfohJaBahngeP")
)

func hasValidAuthKey(r *httpRequest) bool {
	key := r.QueryArgs().PeekBytes(strAuthKey)
	if len(key) == 0 {
		return false
	}

	return hmac.Equal(key, getAuthKey(r, unixTime)) ||
		hmac.Equal(key, getAuthKey(r, unixTime-2-uint64(math.Pow(authKeyWindowBits, 2))))
}

var authKeyMacPool = &sync.Pool{
	New: func() interface{} {
		return hmac.New(sha256.New, authkeySecret)
	},
}

func getAuthKey(r *httpRequest, unixTime uint64) []byte {
	message := make([]byte, 24)
	binary.LittleEndian.PutUint64(message, unixTime>>authKeyWindowBits)
	copy(message[8:], []byte(r.RemoteIP()))

	mac := authKeyMacPool.Get().(hash.Hash)
	mac.Reset()
	defer authKeyMacPool.Put(mac)
	mac.Write(message)

	out := make([]byte, 56)
	base32.HexEncoding.Encode(out, mac.Sum(nil))
	return out
}
