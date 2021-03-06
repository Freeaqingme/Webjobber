package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"golang.org/x/crypto/pbkdf2"
	"hash/crc32"
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/Freeaqingme/fasthttp"
)

const ticketWindowBits = 8

var (
	pbkdfSecret       = []byte("Gu8aimeih3oev2Kae6kooshoo9iej1me7aoquieShueze6Faelang0ruu0ooquai")
	pbkdf2Iterations  = 65535 * 3
	curPowCollection  *powCollection
	prevPowCollection *powCollection
	nextPowCollection *powCollection
)

type powCollection struct {
	created    uint64
	barrier    uint64
	challenges []*powChallenge
}

type powChallenge struct {
	idx    int
	secret []byte
	proof  []byte
}

func solveChallenges(collection *powCollection) {
	procs := runtime.GOMAXPROCS(0) / 2
	if curPowCollection == nil {
		procs = procs * 2
	}

	c := make(chan *powChallenge)
	for i := 0; i < procs; i++ {
		go func(c chan *powChallenge) {
			if runtime.GOMAXPROCS(0) == procs && procs != 1 {
				// We want to do the initial ASAP during start-up.
				runtime.LockOSThread()
			}
			for challenge := range c {
				rawProof := pbkdf2.Key(challenge.secret[:], strEmpty, pbkdf2Iterations, 32, sha256.New)
				challenge.proof = []byte(hex.EncodeToString(rawProof))
			}
		}(c)
	}
	for _, challenge := range collection.challenges {
		c <- challenge
	}
	close(c)
}

func getChallengeForAuthKey(authKey []byte, base64Encode bool) []byte {
	index := powGetCollectionIndexFromAuthKey(authKey)
	for _, challenge := range curPowCollection.challenges {
		if challenge.idx == index && base64Encode {
			buf := make([]byte, base64.StdEncoding.EncodedLen(len(challenge.secret[:])))
			base64.StdEncoding.Encode(buf, challenge.secret[:])

			return buf
		}
		if challenge.idx == index {
			return challenge.secret[:]
		}
	}

	panic("Challenge not found?")
}

func powGetCollectionIndexFromAuthKey(authKey []byte) int {
	return int(math.Mod(float64(crc32.Checksum(authKey, crc32q)), float64(noChallenges)))
}

func regenPowChallenges() {
	c := time.Tick(100 * time.Millisecond)
	var deltaT float64
	for _ = range c {
		barrier := unixTime >> powRegenIntervalBits
		if curPowCollection.barrier < barrier {
			logMessage("Activating ProofOfWork challenges (barrier: %d)", barrier)
			atomic.StoreUintptr(
				(*uintptr)(unsafe.Pointer(&prevPowCollection)),
				(uintptr)(unsafe.Pointer(curPowCollection)),
			)
			atomic.StoreUintptr(
				(*uintptr)(unsafe.Pointer(&curPowCollection)),
				(uintptr)(unsafe.Pointer(nextPowCollection)),
			)

			timeToNextRun := float64(((barrier + 1) << powRegenIntervalBits) - unixTime)
			if (deltaT * 1.05) > timeToNextRun {
				logMessage(`WARNING: Last run (%.2fs) we were out of sync. `+
					`Sleeping remainder of cycle (%.2fs), hoping to get back in sync`,
					deltaT, timeToNextRun*1.05)
				time.Sleep(time.Duration(timeToNextRun*1.05) * time.Second)
				continue
			}
		}

		if nextPowCollection.barrier <= barrier {
			deltaT = updateNextPowCollection(barrier)
		}
	}
}

func updateNextPowCollection(barrier uint64) (deltaT float64) {
	t := time.Now()
	atomic.StoreUintptr(
		(*uintptr)(unsafe.Pointer(&nextPowCollection)),
		(uintptr)(unsafe.Pointer(newPowCollection(barrier+1))),
	)
	deltaT = time.Now().Sub(t).Seconds()
	logMessage("Created next set of ProofOfWork challenges in %.2fs", deltaT)
	intervalSeconds := math.Pow(2, float64(powRegenIntervalBits))
	if deltaT >= intervalSeconds {
		logMessage(
			"WARNING: Generating new Proof of Work challenges took longer (%.2fs) than the set interval (%.2fs)",
			deltaT,
			intervalSeconds)
	}

	return
}

func initPow() {
	pow := newPowCollection(uint64(time.Now().Unix()) >> powRegenIntervalBits)
	curPowCollection = pow
	prevPowCollection = pow
	nextPowCollection = pow

	logMessage("Set initial PoW")
}

func newPowCollection(barrier uint64) *powCollection {
	newPowCollection := &powCollection{
		barrier: barrier,
		created: unixTime,
	}

	for i := 0; i < noChallenges; i++ {
		message := make([]byte, 8)
		message = append(message, byte(i))
		binary.LittleEndian.PutUint64(message, barrier)

		mac := hmac.New(sha256.New, pbkdfSecret)
		mac.Write(message)
		challenge := &powChallenge{
			idx:    i,
			secret: mac.Sum(nil),
		}

		newPowCollection.challenges = append(newPowCollection.challenges, challenge)
	}

	solveChallenges(newPowCollection)
	return newPowCollection
}

func powIsValid(r *httpRequest) bool {
	idx := powGetCollectionIndexFromAuthKey(getAuthKey(r, unixTime, authKeyWindowBits))
	answer := r.PostArgs().PeekBytes([]byte("result"))

	if len(answer) == 0 {
		return false
	}

	for _, challenge := range curPowCollection.challenges {
		if challenge.idx == idx && subtle.ConstantTimeCompare(challenge.proof, answer) == 1 {
			return true
		}
	}

	for _, challenge := range prevPowCollection.challenges {
		if challenge.idx == idx && subtle.ConstantTimeCompare(challenge.proof, answer) == 1 {
			return true
		}
	}

	return false
}

var redirectDstPool = &sync.Pool{
	New: func() interface{} {
		out := make([]byte, 0)
		out = append(out, strUrlRedirect...)
		out = append(out, []byte("00000000000000000000000000000000000000000000000000000000")...)
		out = append(out, strRedirectParam...)
		return out
	},
}

func redirectToServePoW(r *httpRequest) {
	v := redirectDstPool.Get()
	dst := v.([]byte)
	copy(dst[len(strUrlRedirect):len(strUrlRedirect)+56], getAuthKey(r, unixTime, authKeyWindowBits))

	uri := r.RequestURI()
	if !bytes.HasPrefix(r.RequestURI(), strUrlPrefix) {
		dst = append(dst, uri...)
	} else {
		pos := bytes.Index(uri, strRedirectParam)
		if pos != -1 {
			dst = append(dst, uri[pos+len(strRedirectParam):]...)
		} else {
			dst = append(dst, strSlash...)
		}
	}

	r.Response.Header.SetBytesKV(strLocation, dst)
	r.Response.Header.SetStatusCode(302)
	redirectDstPool.Put(v)
}

func powServeHtml(r *httpRequest) {
	r.Response.Header.SetBytesKV(strCacheControlK, strCacheControlV)
	r.Response.Header.SetBytesKV(strPragmaK, strPragmaV)
	r.Response.Header.SetBytesKV(strExpires, strZero)
	r.SetContentTypeBytes(strContentTypeHtml)
	r.Response.AppendBody(filecontentsStart)
	r.Response.AppendBody(getChallengeForAuthKey(getAuthKey(r, unixTime, authKeyWindowBits), true))
	r.Response.AppendBody(filecontentsEnd)
}

func powGrantTicket(r *httpRequest) {
	count := len(strUrlRedirect) + 56 + len(strRedirectParam)

	if len(r.RequestURI()) < count {
		panic("Given URL too short")
	}

	cookie := &fasthttp.Cookie{}
	cookie.SetKeyBytes(strTicketKey)
	cookie.SetValueBytes(getAuthKey(r, unixTime, ticketWindowBits))
	cookie.SetPathBytes([]byte("/"))
	cookie.SetExpire(time.Now().Add(time.Duration(math.Pow(2, float64(ticketWindowBits))) * time.Second))

	r.Response.Header.SetBytesKV(strLocation, r.RequestURI()[count:])
	r.Response.Header.SetStatusCode(302)
	r.Response.Header.SetCookie(cookie)
}

func (r *httpRequest) powHasValidTicket() bool {
	key := r.Request.Header.CookieBytes(strTicketKey)
	valid := authKeyIsValid(key, r, ticketWindowBits)
	return valid
}
