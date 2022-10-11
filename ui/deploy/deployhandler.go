package deploy

import "time"

type deployHandler struct {
	validateFn chan struct{}
	zipping    chan struct{}
	dialing    chan struct{}
	nonce      chan struct{}
	attesting  chan struct{}
	encrypting chan struct{}
	uploading  chan struct{}
	idReturned chan string
	err        chan error
}

func newDeployHandler() *deployHandler {
	return &deployHandler{
		validateFn: make(chan struct{}),
		zipping:    make(chan struct{}),
		dialing:    make(chan struct{}),
		nonce:      make(chan struct{}),
		attesting:  make(chan struct{}),
		encrypting: make(chan struct{}),
		uploading:  make(chan struct{}),
		idReturned: make(chan string),
		err:        make(chan error),
	}
}

func (dh *deployHandler) ValidateFunction() {
	time.Sleep(time.Millisecond * 400)
	dh.validateFn <- struct{}{}
}

func (dh *deployHandler) Zipping() {
	time.Sleep(time.Millisecond * 400)
	dh.zipping <- struct{}{}
}

func (dh *deployHandler) Dialing() {
	time.Sleep(time.Millisecond * 400)
	dh.dialing <- struct{}{}
}

func (dh *deployHandler) SendNonce() {
	time.Sleep(time.Millisecond * 400)
	dh.nonce <- struct{}{}
}

func (dh *deployHandler) Attesting() {
	time.Sleep(time.Millisecond * 400)
	dh.attesting <- struct{}{}
}

func (dh *deployHandler) EncryptingFunction() {
	time.Sleep(time.Millisecond * 400)
	dh.encrypting <- struct{}{}
}

func (dh *deployHandler) Uploading() {
	time.Sleep(time.Millisecond * 400)
	dh.uploading <- struct{}{}
}

func (dh *deployHandler) IDReturned(id string) {
	time.Sleep(time.Millisecond * 400)
	dh.idReturned <- id
}

func (dh *deployHandler) Error(err error) {
	dh.err <- err
}
