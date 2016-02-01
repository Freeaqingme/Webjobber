package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"hash/crc32"
	"io/ioutil"
	"log"
	"math"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/Freeaqingme/fasthttp"
	"github.com/vharitonsky/iniflags"
)

const authKeyWindowBits = 3

var (
	strCacheControlK   = []byte("Cache-Control")
	strCacheControlV   = []byte("no-cache, no-store, must-revalidate")
	strPragmaK         = []byte("Pragma")
	strPragmaV         = []byte("no-cache")
	strExpires         = []byte("Expires")
	strZero            = []byte("0")
	strAuthKey         = []byte("authkey")
	strContentTypeHtml = []byte("text/html; charset=utf-8")
	strLocation        = []byte("Location")
	strRedirectParam   = []byte("&redirect=")
	strSlash           = []byte("/")
	strUrlPrefix       = []byte("/_securityValidation/")
	strUrlRedirect     = append(strUrlPrefix, []byte("?authkey=")...)
)

var (
	listenAddrs          = flag.String("listenAddrs", ":8098", "A list of TCP addresses to listen to HTTP requests. Leave empty if you don't need http")
	authkeySecret        = []byte("phu8sae0Reih8vohngohjaix8zaeshei1Oochaideiz7jieti1ahfohJaBahngeP")
	salt                 = []byte("")
	noChallenges         = 512
	pbkdfSecret          = []byte("Gu8aimeih3oev2Kae6kooshoo9iej1me7aoquieShueze6Faelang0ruu0ooquai")
	pbkdf2Iterations     = 65536 * 3
	crc32q               = crc32.MakeTable(0xD5828281)
	powRegenIntervalBits = uint(8)

	curPowCollection  *powCollection
	prevPowCollection *powCollection
	nextPowCollection *powCollection
	filecontentsStart []byte
	filecontentsEnd   []byte
	unixTime          uint64
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

func main() {
	iniflags.Parse()

	unixTime = uint64(time.Now().Unix())
	initPow()
	go regenPowChallenges()
	go updateTime()

	loadHtmlFile()
	var addr string
	for _, addr = range strings.Split(*listenAddrs, ",") {
		go serveHttp(addr)
	}

	waitForeverCh := make(chan int)
	<-waitForeverCh
}

func loadHtmlFile() {
	dat, err := ioutil.ReadFile("./serve.html")
	if err != nil {
		panic(err)
	}

	pos := bytes.Index(dat, []byte("CHALLENGEPLACEHOLDER"))
	if pos == -1 {
		panic("Placeholder not found")
	}
	filecontentsStart = dat[:pos]
	filecontentsEnd = dat[pos+len("CHALLENGEPLACEHOLDER"):]
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
		fmt.Println(message)

		challenge := &powChallenge{
			idx:    i,
			secret: mac.Sum(nil),
		}

		newPowCollection.challenges = append(newPowCollection.challenges, challenge)
	}

	solveChallenges(newPowCollection)
	return newPowCollection
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
				challenge.proof = pbkdf2.Key(challenge.secret[:], salt, pbkdf2Iterations, 32, sha256.New)
			}
		}(c)
	}
	for _, challenge := range collection.challenges {
		c <- challenge
	}
	close(c)
}

func updateTime() {
	c := time.Tick(100 * time.Millisecond)
	for now := range c {
		atomic.SwapUint64(&unixTime, uint64(now.Unix()))
	}
}

func serveHttp(addr string) {
	if addr == "" {
		return
	}
	ln := listen(addr)
	logMessage("Listening http on [%s]", addr)
	serve(ln)
}

func listen(addr string) net.Listener {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logFatal("Cannot listen [%s]: [%s]", addr, err)
	}
	return ln
}

func serve(ln net.Listener) {
	s := &fasthttp.Server{
		Handler: requestHandler,
		Name:    "WebJobber",
	}
	s.Serve(ln)
}

func getChallengeForAuthKey(authKey []byte, base64Encode bool) []byte {
	index := int(math.Mod(float64(crc32.Checksum(authKey, crc32q)), float64(noChallenges)))
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

func requestHandler(ctx *fasthttp.RequestCtx) {
	uri := ctx.RequestURI()

	if isAuthenticated(ctx) {
		// passthrough
		return
	}
	if !bytes.HasPrefix(uri, strUrlPrefix) {
		redirectToValidate(ctx, true)
		return
	}

	if !hasValidAuthKey(ctx) {
		redirectToValidate(ctx, false)
		return
	}

	ctx.Response.Header.SetBytesKV(strCacheControlK, strCacheControlV)
	ctx.Response.Header.SetBytesKV(strPragmaK, strPragmaV)
	ctx.Response.Header.SetBytesKV(strExpires, strZero)
	ctx.SetContentTypeBytes(strContentTypeHtml)
	ctx.Response.AppendBody(filecontentsStart)
	ctx.Response.AppendBody(getChallengeForAuthKey(getAuthKey(ctx, unixTime), true))
	ctx.Response.AppendBody(filecontentsEnd)
}

func hasValidAuthKey(ctx *fasthttp.RequestCtx) bool {
	key := ctx.QueryArgs().PeekBytes(strAuthKey)
	if len(key) == 0 {
		return false
	}

	return hmac.Equal(key, getAuthKey(ctx, unixTime)) ||
		hmac.Equal(key, getAuthKey(ctx, unixTime-2-uint64(math.Pow(authKeyWindowBits, 2))))
}

var authKeyPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 8+16)
	},
}

func getAuthKey(ctx *fasthttp.RequestCtx, unixTime uint64) []byte {
	v := authKeyPool.Get()
	message := v.([]byte)

	binary.LittleEndian.PutUint64(message, unixTime>>authKeyWindowBits)
	copy(message[8:], []byte(ctx.RemoteIP()))

	mac := hmac.New(sha256.New, authkeySecret)
	mac.Write(message)
	mac.Sum(nil)

	authKeyPool.Put(v)
	return []byte(base32.HexEncoding.EncodeToString(mac.Sum(nil)))[:32]
}

func isAuthenticated(ctx *fasthttp.RequestCtx) bool {
	// todo
	return false
}

var redirectDstPool = &sync.Pool{
	New: func() interface{} {
		out := make([]byte, 0)
		out = append(out, strUrlRedirect...)
		out = append(out, []byte("00000000000000000000000000000000")...)
		out = append(out, strRedirectParam...)
		return out
	},
}

func redirectToValidate(ctx *fasthttp.RequestCtx, updateRedirectParam bool) {
	v := redirectDstPool.Get()
	dst := v.([]byte)

	copy(dst[len(strUrlRedirect):len(strUrlRedirect)+32], getAuthKey(ctx, unixTime))

	uri := ctx.RequestURI()
	if updateRedirectParam {
		dst = append(dst, uri...)
	} else {
		pos := bytes.Index(uri, strRedirectParam)
		if pos != -1 {
			dst = append(dst, uri[pos+len(strRedirectParam):]...)
		} else {
			dst = append(dst, strSlash...)
		}
	}

	ctx.Response.Header.SetBytesKV(strLocation, dst)
	ctx.Response.Header.SetStatusCode(302)
	redirectDstPool.Put(v)
}

func logRequestError(h *fasthttp.RequestHeader, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	logMessage("%s - %s - %s. %s", h.RequestURI(), h.Referer(), h.UserAgent(), msg)
}

func logMessage(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("%s\n", msg)
}

func logFatal(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Fatalf("%s\n", msg)
}
