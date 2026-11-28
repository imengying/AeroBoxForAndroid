package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/quicvarint"
)

func TestFrameFINRequiresBoundary(t *testing.T) {
	for _, raw := range [][]byte{{0x40}, {0}, {0, 3}, {0, 3, 1}, {0, 0x40}} {
		if _, _, err := readFrame(bytes.NewReader(raw)); err != io.ErrUnexpectedEOF {
			t.Fatalf("truncated %x: got %v", raw, err)
		}
	}
	r := bytes.NewReader([]byte{0, 0, 0, 1, 42})
	for _, want := range [][]byte{{}, {42}} {
		typ, payload, err := readFrame(r)
		if err != nil || typ != 0 || !bytes.Equal(payload, want) {
			t.Fatalf("complete frame: type=%d payload=%x err=%v", typ, payload, err)
		}
	}
	if _, _, err := readFrame(r); err != io.EOF {
		t.Fatalf("frame boundary: got %v", err)
	}
}

func TestInterleavedInitialConnections(t *testing.T) {
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan struct{}, 2)
	for _, name := range []string{"first.invalid", "second.invalid"} {
		go func() {
			_, _ = quic.DialAddr(ctx, socket.LocalAddr().String(), &tls.Config{
				ServerName: name, NextProtos: []string{"h3"}, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
			}, nil)
			done <- struct{}{}
		}()
	}
	defer func() { cancel(); <-done; <-done }()
	if err := socket.SetReadDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	packets := make(map[string][][]byte)
	peers := make(map[string]net.Addr)
	for {
		buf := make([]byte, 2048)
		n, peer, err := socket.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		packets[peer.String()] = append(packets[peer.String()], buf[:n])
		peers[peer.String()] = peer
		ready := len(packets) == 2
		for _, pending := range packets {
			ready = ready && len(pending) >= 2
		}
		if ready {
			break
		}
	}
	capture := packetCapture{output: t.TempDir()}
	// Deliberately interleave the first fragments; the old single buffer
	// combined their offset-zero data and rejected distinct connections.
	for i := 0; i < 2; i++ {
		for name, pending := range packets {
			if err := capture.recordInitial(pending[i], peers[name]); err != nil {
				t.Fatal(err)
			}
		}
	}
	seen := make(map[string]bool)
	for _, peer := range peers {
		if err := capture.selectPeer(peer); err != nil {
			t.Fatal(err)
		}
		hello, err := os.ReadFile(filepath.Join(capture.output, "client-hello.bin"))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"first.invalid", "second.invalid"} {
			if bytes.Contains(hello, []byte(name)) {
				if seen[name] {
					t.Fatalf("selected the same ClientHello for different peers: %s", name)
				}
				seen[name] = true
			}
		}
	}
	if len(seen) != 2 {
		t.Fatalf("did not preserve both ClientHellos: %v", seen)
	}
}

// Construct authenticated packets with independent header and key DCIDs. The
// server can change the former without changing the Initial traffic secrets.
func initialPacket(t *testing.T, originalDCID, wireDCID []byte, number uint32, frames []byte) []byte {
	t.Helper()
	salt, err := hex.DecodeString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
	if err != nil {
		t.Fatal(err)
	}
	extract := hmac.New(sha256.New, salt)
	extract.Write(originalDCID)
	secret := expand(extract.Sum(nil), "client in", 32)
	block, err := aes.NewCipher(expand(secret, "quic key", 16))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	header := append([]byte{0xc3, 0, 0, 0, 1, byte(len(wireDCID))}, wireDCID...)
	header = append(header, 0, 0) // Empty source CID and token.
	header = quicvarint.Append(header, uint64(4+len(frames)+aead.Overhead()))
	offset := len(header)
	header = binary.BigEndian.AppendUint32(header, number)
	nonce := expand(secret, "quic iv", 12)
	for i := 0; i < 4; i++ {
		nonce[len(nonce)-1-i] ^= byte(number >> (8 * i))
	}
	packet := aead.Seal(header, nonce, frames, header)
	hp, err := aes.NewCipher(expand(secret, "quic hp", 16))
	if err != nil {
		t.Fatal(err)
	}
	var mask [16]byte
	hp.Encrypt(mask[:], packet[offset+4:offset+20])
	packet[0] ^= mask[0] & 15
	for i := 0; i < 4; i++ {
		packet[offset+i] ^= mask[i+1]
	}
	return packet
}

func cryptoFrame(offset uint64, data []byte) []byte {
	frame := quicvarint.Append([]byte{6}, offset)
	frame = quicvarint.Append(frame, uint64(len(data)))
	return append(frame, data...)
}

func TestChangedInitialDCIDReassemblesSeparateConnectionsOnSamePeer(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4433}
	firstCID, secondCID := []byte("firstcid"), []byte("secondid")
	serverCID := []byte("scid")
	firstHello, secondHello := []byte{1, 0, 0, 6, 'f', 'i', 'r', 's', 't', '!'}, []byte{1, 0, 0, 6, 's', 'e', 'c', 'o', 'n', 'd'}
	capture := packetCapture{}
	for _, packet := range [][]byte{
		initialPacket(t, firstCID, firstCID, 0, cryptoFrame(0, firstHello[:5])),
		initialPacket(t, secondCID, secondCID, 0, cryptoFrame(0, secondHello[:7])),
		// Even identical new wire CIDs must select by the authenticated key.
		initialPacket(t, firstCID, serverCID, 1, cryptoFrame(5, firstHello[5:])),
		initialPacket(t, secondCID, serverCID, 1, cryptoFrame(7, secondHello[7:])),
		// Completed ClientHellos still authenticate later Initial packets.
		initialPacket(t, firstCID, []byte("next"), 2, cryptoFrame(0, firstHello)),
		initialPacket(t, secondCID, []byte("next"), 2, []byte{1}),
	} {
		if err := capture.recordInitial(packet, peer); err != nil {
			t.Fatal(err)
		}
	}
	if len(capture.hellos) != 2 {
		t.Fatalf("changed wire CID created extra connections: %d", len(capture.hellos))
	}
	for _, connection := range []struct{ cid, hello []byte }{{firstCID, firstHello}, {secondCID, secondHello}} {
		got := capture.hellos[initialKey{peer.String(), hex.EncodeToString(connection.cid)}]
		if got == nil || !bytes.Equal(got.originalDCID, connection.cid) || !bytes.Equal(got.complete, connection.hello) {
			t.Fatalf("did not preserve original connection %x", connection.cid)
		}
	}
}

func TestInitialAuthenticationFailureDoesNotHideAuthenticatedFrameError(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4433}
	cid := []byte("original")
	partial := []byte{1, 0, 0, 6, 'f'}
	capture := packetCapture{}
	if err := capture.recordInitial(initialPacket(t, cid, cid, 0, cryptoFrame(0, partial)), peer); err != nil {
		t.Fatal(err)
	}
	corrupt := initialPacket(t, cid, []byte("scid"), 1, cryptoFrame(5, []byte("irst!")))
	corrupt[len(corrupt)-1] ^= 1
	if err := capture.recordInitial(corrupt, peer); !errors.Is(err, errInitialAuthentication) {
		t.Fatalf("corrupt authentication: %v", err)
	}
	for _, invalid := range []struct {
		frame []byte
		want  string
	}{
		{[]byte{0x1f}, "unexpected initial frame"},
		{cryptoFrame(4, []byte("other!")), "conflicting CRYPTO"},
	} {
		err := capture.recordInitial(initialPacket(t, cid, []byte("scid"), 2, invalid.frame), peer)
		if err == nil || errors.Is(err, errInitialAuthentication) || !strings.Contains(err.Error(), invalid.want) {
			t.Fatalf("authenticated malformed frame should fail without trying a new connection: %v", err)
		}
	}
	if len(capture.hellos) != 1 {
		t.Fatalf("failed packet created a new connection: %d", len(capture.hellos))
	}
	if got := capture.hellos[initialKey{peer.String(), hex.EncodeToString(cid)}]; len(got.complete) != 0 || !bytes.Equal(got.data[:len(partial)], partial) {
		t.Fatal("rejected packet changed reassembly")
	}
}

func TestInitialLengthCannotUseCoalescedPacketForHeaderProtection(t *testing.T) {
	packet := []byte{0xc3, 0, 0, 0, 1, 8, 'o', 'r', 'i', 'g', 'i', 'n', 'a', 'l', 0, 0, 1}
	packet = append(packet, make([]byte, 64)...)
	var capture initialCapture
	if err := capture.add(packet); err == nil || errors.Is(err, errInitialAuthentication) {
		t.Fatalf("short packet followed by unrelated bytes: %v", err)
	}
}
