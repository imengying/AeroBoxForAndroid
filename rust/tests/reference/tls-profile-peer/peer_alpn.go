package main

import (
	"bytes"
	"errors"
)

func checkPeerALPN(hello clientHello, o peerOptions) error {
	if o.UnsolicitedALPN {
		if _, offered := hello.extensions[16]; offered || o.AllowNoALPN || o.OmitALPN || o.ALPS != 0 || (o.SelectedALPN != "" && o.SelectedALPN != "h2") {
			return errors.New("unsolicited-alpn requires absent ALPN offer, ALPS=0 and h2 selection")
		}
		return nil
	}
	if o.AllowNoALPN {
		if _, offered := hello.extensions[16]; offered || o.ALPS != 0 || !o.OmitALPN {
			return errors.New("allow-no-alpn requires absent ALPN offer, ALPS=0 and omit-alpn")
		}
		return nil
	}
	alpnList := reader{p: hello.extensions[16]}
	alpn := reader{p: alpnList.vector(2)}
	h2 := false
	for len(alpn.p) > 0 && alpn.err == nil {
		if bytes.Equal(alpn.vector(1), []byte("h2")) {
			h2 = true
		}
	}
	if !h2 {
		return errors.New("h2 not offered")
	}
	return nil
}
