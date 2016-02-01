package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"hash"
	"math"
	"sync"

	"github.com/Freeaqingme/fasthttp"
)

var (
	authkeySecret = []byte("phu8sae0Reih8vohngohjaix8zaeshei1Oochaideiz7jieti1ahfohJaBahngeP")
)

func hasValidAuthKey(ctx *fasthttp.RequestCtx) bool {
	key := ctx.QueryArgs().PeekBytes(strAuthKey)
	if len(key) == 0 {
		return false
	}

	return hmac.Equal(key, getAuthKey(ctx, unixTime)) ||
		hmac.Equal(key, getAuthKey(ctx, unixTime-2-uint64(math.Pow(authKeyWindowBits, 2))))
}

var authKeyMacPool = &sync.Pool{
	New: func() interface{} {
		return hmac.New(sha256.New, authkeySecret)
	},
}

func getAuthKey(ctx *fasthttp.RequestCtx, unixTime uint64) []byte {
	message := make([]byte, 24)
	binary.LittleEndian.PutUint64(message, unixTime>>authKeyWindowBits)
	copy(message[8:], []byte(ctx.RemoteIP()))

	mac := authKeyMacPool.Get().(hash.Hash)
	mac.Reset()
	defer authKeyMacPool.Put(mac)
	mac.Write(message)

	out := make([]byte, 56)
	base32.HexEncoding.Encode(out, mac.Sum(nil))
	return out
}
