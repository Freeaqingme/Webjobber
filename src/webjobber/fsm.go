package main

import (
	"bytes"
)

const (
	fsmVoid = 1 << iota
	fsmHasTicket
	fsmRequestedPoWPage
	fsmProtectedUrl
	//	fsmHitRatelimit
	//	fsmHighLoad
	fsmHasValidAuthKey
	fsmRedirectToPoW
	fsmIsPost
	fsmServePoW
	fsmPowIsValid
	fsmPoWGrantTicket
)

var fsmTransitions = make(map[int]*fsmTransition)
var fsmEndpoints = make(map[int]*fsmEndpoint)

type fsmTransition struct {
	id      int
	check   func(*httpRequest) bool
	ifTrue  int
	ifFalse int
}

type fsmEndpoint struct {
	id      int
	command func(*httpRequest)
}

// See also fsm.dia that visualizes this flow
func init() {
	reg := fsmRegisterTransition
	reg(&fsmTransition{fsmHasTicket, (*httpRequest).hasTicket, fsmVoid /* fsmHitRateLimit */, fsmRequestedPoWPage})
	reg(&fsmTransition{fsmRequestedPoWPage, (*httpRequest).requestedPoWPage, fsmHasValidAuthKey, fsmProtectedUrl})
	reg(&fsmTransition{fsmHasValidAuthKey, (*httpRequest).hasValidAuthKey, fsmIsPost, fsmRedirectToPoW})
	reg(&fsmTransition{fsmIsPost, (*httpRequest).IsPost, fsmPowIsValid, fsmServePoW})
	reg(&fsmTransition{fsmPowIsValid, powIsValid, fsmPoWGrantTicket, fsmServePoW})
	reg(&fsmTransition{fsmProtectedUrl, (*httpRequest).isProtectedUrl, fsmRedirectToPoW, fsmVoid /* fsmHighLoad */})

	fsmRegisterEndpoint(&fsmEndpoint{fsmRedirectToPoW, redirectToServePoW})
	fsmRegisterEndpoint(&fsmEndpoint{fsmServePoW, powServeHtml})
	fsmRegisterEndpoint(&fsmEndpoint{fsmPoWGrantTicket, powGrantTicket})
}

func fsmEnter(r *httpRequest) {
	fsmRun(r, fsmHasTicket, 0)
}

func fsmRun(r *httpRequest, id int, count int) {
	if count >= 100 {
		panic("Reached max (100) transitions.")
	}

	if fsmEndpoints[id] != nil {
		fsmEndpoints[id].command(r)
		return
	}

	if fsmTransitions[id] == nil {
		panic("Asked to move to a transition that does not exist")
	}

	res := fsmTransitions[id].check(r)
	if res {
		id = fsmTransitions[id].ifTrue
	} else {
		id = fsmTransitions[id].ifFalse
	}

	if id == fsmVoid {
		return
	}

	count++
	fsmRun(r, id, count)
}

func fsmRegisterTransition(transition *fsmTransition) {
	if fsmTransitions[transition.id] != nil {
		panic("Same transition id registered twice")
	}

	if fsmEndpoints[transition.id] != nil {
		panic("Specified id is an endpoint, cannot re-register as transition")
	}

	fsmTransitions[transition.id] = transition
}

func fsmRegisterEndpoint(endpoint *fsmEndpoint) {
	if fsmEndpoints[endpoint.id] != nil {
		panic("Same endpoint id registered twice")
	}

	if fsmTransitions[endpoint.id] != nil {
		panic("Specified id is a transition, cannot re-register as endpoint")
	}

	if endpoint.command == nil {
		panic("EndPoint command was nil.")
	}

	fsmEndpoints[endpoint.id] = endpoint
}

func (r *httpRequest) hasTicket() bool {
	return false // todo
}

func (r *httpRequest) isProtectedUrl() bool {
	return true // todo
}

func (r *httpRequest) requestedPoWPage() bool {
	return bytes.HasPrefix(r.RequestURI(), strUrlPrefix)
}
