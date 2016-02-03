package main

import (
	"bytes"
	"flag"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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
	strEmpty             = []byte("")
	noChallenges         = 1 //12
	crc32q               = crc32.MakeTable(0xD5828281)
	powRegenIntervalBits = uint(8)

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

func isAuthenticated(ctx *fasthttp.RequestCtx) bool {
	// todo
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

func redirectToValidate(ctx *fasthttp.RequestCtx, updateRedirectParam bool) {
	v := redirectDstPool.Get()
	dst := v.([]byte)
	copy(dst[len(strUrlRedirect):len(strUrlRedirect)+56], getAuthKey(ctx, unixTime))

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
