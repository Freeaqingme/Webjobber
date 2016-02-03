package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"golang.org/x/crypto/pbkdf2"
	"hash/crc32"
	"math"
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"
)

var (
	pbkdfSecret       = []byte("Gu8aimeih3oev2Kae6kooshoo9iej1me7aoquieShueze6Faelang0ruu0ooquai")
	pbkdf2Iterations  = 65535 * 3
	curPowCollection  *powCollection
	prevPowCollection *powCollection
	nextPowCollection *powCollection
)

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
