package main

import (
	"bytes"
)

func flowEnter(r *httpRequest) {

	if r.hasTicket() {
		flowCheckHitRatelimit(r)
		return
	} else {
		flowCheckProtectedUrl(r)
	}

}

func flowCheckProtectedUrl(r *httpRequest) {
	if true {
		redirectToValidate(r)
	} else {
		flowCheckLoad(r)
	}
}

func flowCheckLoad(r *httpRequest) {
	if hasHighLoad() {
		redirectToValidate(r)
	} else {
		flowCheckHitRatelimit(r)
	}
}

func hasHighLoad() {
	return false
}

func flowCheckHitRatelimit(r *httpRequest) {
	if ! r.reachedRateLimit() {
		flowCheckModSecurity()
		return
	}

	if r.hasTicket() {
		flowRequestReject()
		return
	}

	redirectToValidate(r)
}

func flowCheckModSecurity() {
	if flowRequestIsMalicious() {
		flowRequestReject()
		return
	}

	flowPassthrough()
}

func flowPassthrough() {
	// todo
}

func redirectToValidate(r *httpRequest) {
	v := redirectDstPool.Get()
	dst := v.([]byte)
	copy(dst[len(strUrlRedirect):len(strUrlRedirect)+56], getAuthKey(r, unixTime))

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

func flowRequestReject() {
	// todo
}

func flowRequestIsMalicious() bool {
	return false
}

func (r *httpRequest) reachedRateLimit() bool {
	return false // todo
}

func (r *httpRequest) hasTicket() bool {
	return false // todo
}