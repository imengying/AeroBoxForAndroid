// Raw QUIC/H3 observer for the fixed original Cronet and production Rust clients.
// The advertised QPACK capacity is zero: both clients must use static/literal
// request fields. Dynamic compression is a separate interoperability exercise.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/quic-go/qpack"
	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/quicvarint"
)

type packetCapture struct {
	net.PacketConn
	output  string
	mu      sync.Mutex
	packets int
	hellos  map[initialKey]*initialCapture
}

type initialKey struct{ peer, cid string }

// A network change can replace a connection before its first ClientHello is
// complete. Never combine CRYPTO offsets from different Initial connections.
func (p *packetCapture) recordInitial(packet []byte, peer net.Addr) error {
	if len(packet) < 7 || packet[0]&0xf0 != 0xc0 || binary.BigEndian.Uint32(packet[1:5]) != 1 {
		return nil
	}
	size := int(packet[5])
	if size > 20 || len(packet) <= 6+size {
		return fmt.Errorf("invalid initial DCID")
	}
	key := initialKey{peer.String(), hex.EncodeToString(packet[6 : 6+size])}
	if p.hellos == nil {
		p.hellos = make(map[initialKey]*initialCapture)
	}
	// A wire DCID can change to the server's SCID during the handshake. Only
	// successful authentication identifies the original connection: trying a
	// key must not merge CRYPTO from another connection on the same UDP peer.
	for known, hello := range p.hellos {
		if known.peer != key.peer {
			continue
		}
		err := hello.add(packet)
		if !errors.Is(err, errInitialAuthentication) {
			return err // Includes authenticated malformed frames, not only success.
		}
	}
	// No existing key authenticated it. A genuinely new connection derives
	// its Initial keys from this packet's DCID and gets its own reassembly.
	hello := &initialCapture{}
	if err := hello.add(packet); err != nil {
		return err
	}
	if len(p.hellos) >= 8 {
		return fmt.Errorf("too many Initial connections in observation fixture")
	}
	p.hellos[key] = hello
	return nil
}

func (p *packetCapture) selectPeer(peer net.Addr) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var selected []byte
	var cid string
	for key, hello := range p.hellos {
		if key.peer != peer.String() || len(hello.complete) == 0 {
			continue
		}
		if selected != nil && !bytes.Equal(selected, hello.complete) {
			return fmt.Errorf("ambiguous ClientHello for accepted peer")
		}
		selected, cid = hello.complete, key.cid
	}
	if selected == nil {
		return fmt.Errorf("missing ClientHello for accepted peer")
	}
	if err := os.WriteFile(filepath.Join(p.output, "client-hello.bin"), selected, 0600); err != nil {
		return err
	}
	data, err := json.Marshal(map[string]any{"peer": peer.String(), "initial_cid": cid, "observed_initial_connections": len(p.hellos)})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(p.output, "accepted-connection.json"), data, 0600)
}

func (p *packetCapture) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, e := p.PacketConn.ReadFrom(b)
	if n > 0 {
		p.mu.Lock()
		if p.packets < 64 {
			file, err := os.OpenFile(filepath.Join(p.output, "datagrams.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
			must(err)
			must(json.NewEncoder(file).Encode(map[string]any{"length": n, "peer": a.String(), "data": hex.EncodeToString(b[:n])}))
			must(file.Close())
			p.packets++
			must(p.recordInitial(b[:n], a))
		}
		p.mu.Unlock()
	}
	return n, a, e
}
func must(e error) {
	if e != nil {
		panic(e)
	}
}
func readVar(r io.Reader) (uint64, error) { return quicvarint.Read(quicvarint.NewReader(r)) }
func readPrefix(r io.Reader, first byte, bits uint) (uint64, error) {
	mask := uint64(1<<bits) - 1
	value := uint64(first) & mask
	if value < mask {
		return value, nil
	}
	for shift := uint(0); shift < 63; shift += 7 {
		var b [1]byte
		if _, e := io.ReadFull(r, b[:]); e != nil {
			return 0, e
		}
		value += uint64(b[0]&127) << shift
		if b[0]&128 == 0 {
			return value, nil
		}
	}
	return 0, fmt.Errorf("QPACK integer overflow")
}
func appendPrefix(out []byte, flag byte, bits uint, value uint64) []byte {
	mask := uint64(1<<bits) - 1
	if value < mask {
		return append(out, flag|byte(value))
	}
	out = append(out, flag|byte(mask))
	value -= mask
	for value >= 128 {
		out = append(out, byte(value&127)|128)
		value >>= 7
	}
	return append(out, byte(value))
}
func frame(t uint64, b []byte) []byte {
	return append(quicvarint.Append(quicvarint.Append(nil, t), uint64(len(b))), b...)
}
func readFrame(r io.Reader) (uint64, []byte, error) {
	// EOF is a clean FIN only at a frame boundary. A truncated type, length
	// or payload must not be mistaken for FIN after enough echo data arrived.
	var first [1]byte
	if _, e := io.ReadFull(r, first[:]); e != nil {
		return 0, nil, e
	}
	t, e := readVar(io.MultiReader(bytes.NewReader(first[:]), r))
	if e != nil {
		return 0, nil, incompleteFrame(e)
	}
	n, e := readVar(r)
	if e != nil {
		return 0, nil, incompleteFrame(e)
	}
	if n > 1<<20 {
		return 0, nil, fmt.Errorf("frame exceeds fixture limit")
	}
	b := make([]byte, n)
	_, e = io.ReadFull(r, b)
	return t, b, incompleteFrame(e)
}

func incompleteFrame(e error) error {
	if e == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return e
}

type streamCapture struct {
	ID      int64
	Type    uint64
	Data    string
	Headers []qpack.HeaderField
	Bytes   int
	End     string `json:",omitempty"`
}

func captureQUIC(output string, cert tls.Certificate) {
	dynamic := os.Getenv("AEROBOX_NAIVE_DYNAMIC_QPACK") == "1"
	informational := os.Getenv("AEROBOX_NAIVE_INFORMATIONAL") == "1"
	must(os.Mkdir(output, 0700))
	ca := filepath.Join(output, "ca.pem")
	must(os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600))
	socket, e := net.ListenPacket("udp4", "127.0.0.1:0")
	must(e)
	defer socket.Close()
	capture := &packetCapture{PacketConn: socket, output: output}
	listener, e := quic.Listen(capture, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}, &quic.Config{MaxIdleTimeout: 20 * time.Second, MaxIncomingStreams: 100, MaxIncomingUniStreams: 16})
	must(e)
	defer listener.Close()
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": "ready", "port": listener.Addr().(*net.UDPAddr).Port, "ca_pem": ca, "server_name": "naive.test"}))
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	var conn *quic.Conn
	var control *quic.SendStream
	var firstStream *quic.Stream
	var firstType uint64
	var firstData []byte
	target := os.Getenv("AEROBOX_NAIVE_CAPTURE_TARGET")
	for {
		conn, e = listener.Accept(ctx)
		must(e)
		control, e = conn.OpenUniStreamSync(ctx)
		must(e)
		_, e = control.Write(append([]byte{0}, frame(4, []byte{1, 0, 7, 0})...))
		must(e)
		if target == "" {
			break
		}
		// A system-wide Android VPN also receives background DNS and
		// connectivity probes. Select the explicitly requested test tunnel.
		firstContext, stop := context.WithTimeout(ctx, 3*time.Second)
		firstStream, e = conn.AcceptStream(firstContext)
		stop()
		if e != nil {
			_ = conn.CloseWithError(0x100, "no observation request")
			continue
		}
		must(firstStream.SetReadDeadline(time.Now().Add(3 * time.Second)))
		firstType, firstData, e = readFrame(firstStream)
		must(e)
		if firstType != 1 {
			panic("expected HEADERS")
		}
		selected := false
		next := qpack.NewDecoder().Decode(firstData)
		for {
			field, err := next()
			if err == io.EOF {
				break
			}
			must(err)
			if field.Name == ":authority" && field.Value == target {
				selected = true
			}
		}
		if selected {
			break
		}
		_ = conn.CloseWithError(0x100, "outside observation target")
	}
	must(capture.selectPeer(conn.RemoteAddr()))
	defer conn.CloseWithError(0x100, "capture complete")
	var mu sync.Mutex
	var streams []streamCapture
	var feedback []string
	acks := make(chan uint64, 2)
	var dynamicEncoder *quic.SendStream
	if dynamic {
		dynamicEncoder, e = conn.OpenUniStreamSync(ctx)
		must(e)
		_, e = dynamicEncoder.Write([]byte{2})
		must(e)
	}
	appendCapture := func(s streamCapture) { mu.Lock(); defer mu.Unlock(); streams = append(streams, s) }
	uniDone := make(chan struct{})
	go func() {
		defer close(uniDone)
		for {
			stream, e := conn.AcceptUniStream(ctx)
			if e != nil {
				return
			}
			go func() {
				typ, e := readVar(stream)
				if e != nil {
					return
				}
				entry := streamCapture{ID: int64(stream.StreamID()), Type: typ}
				if typ == 0 {
					for {
						t, data, e := readFrame(stream)
						if e != nil {
							return
						}
						entry.Type = t
						entry.Data = hex.EncodeToString(data)
						appendCapture(entry)
					}
				} else {
					// Capture the stream type immediately; critical streams normally stay open.
					appendCapture(entry)
					if dynamic && typ == 3 {
						for {
							var first [1]byte
							if _, e := io.ReadFull(stream, first[:]); e != nil {
								return
							}
							bits, kind := uint(6), "increment"
							if first[0]&128 != 0 {
								bits, kind = 7, "ack"
							} else if first[0]&64 != 0 {
								kind = "cancel"
							}
							value, e := readPrefix(stream, first[0], bits)
							must(e)
							mu.Lock()
							feedback = append(feedback, fmt.Sprintf("%s:%d", kind, value))
							mu.Unlock()
							if kind == "ack" {
								acks <- value
							}
						}
					}
				}
			}()
		}
	}()
	for i := 0; i < 2; i++ {
		stream, typ, data := firstStream, firstType, firstData
		if i != 0 || stream == nil {
			stream, e = conn.AcceptStream(ctx)
			must(e)
			must(stream.SetDeadline(time.Now().Add(15 * time.Second)))
			typ, data, e = readFrame(stream)
			must(e)
		}
		must(stream.SetDeadline(time.Now().Add(15 * time.Second)))
		if typ != 1 {
			panic("expected HEADERS")
		}
		entry := streamCapture{ID: int64(stream.StreamID()), Type: typ, Data: hex.EncodeToString(data)}
		next := qpack.NewDecoder().Decode(data)
		for {
			field, e := next()
			if e == io.EOF {
				break
			}
			must(e)
			entry.Headers = append(entry.Headers, field)
		}
		if informational {
			// The fixed Cronet Naive wrapper consumes 100, but exposes 103 as
			// an error. Keep parity acceptance on its supported response path.
			for _, status := range []string{"100"} {
				var interim bytes.Buffer
				encoder := qpack.NewEncoder(&interim)
				must(encoder.WriteField(qpack.HeaderField{Name: ":status", Value: status}))
				must(encoder.WriteField(qpack.HeaderField{Name: "x-interim", Value: "not-the-final-response"}))
				must(encoder.Close())
				_, e = stream.Write(frame(1, interim.Bytes()))
				must(e)
			}
		}
		var headers bytes.Buffer
		encoder := qpack.NewEncoder(&headers)
		must(encoder.WriteField(qpack.HeaderField{Name: ":status", Value: "200"}))
		must(encoder.WriteField(qpack.HeaderField{Name: "padding", Value: "reference"}))
		must(encoder.Close())
		response := headers.Bytes()
		if dynamic {
			// Required Insert Count=1, Base=1; static :status=200 and
			// dynamic index 0. Capacity refers to the client's SETTINGS.
			response = []byte{2, 0, 0xd9, 0x80}
		}
		_, e = stream.Write(frame(1, response))
		must(e)
		if dynamic && i == 0 {
			instructions := appendPrefix(nil, 0x20, 5, 65536)
			instructions = append(instructions, 0x47)
			instructions = append(instructions, []byte("padding")...)
			instructions = append(instructions, 9)
			instructions = append(instructions, []byte("reference")...)
			for _, b := range instructions {
				_, e = dynamicEncoder.Write([]byte{b})
				must(e)
			}
		}
		if dynamic {
			select {
			case received := <-acks:
				if received != uint64(stream.StreamID()) {
					panic("wrong QPACK acknowledgement")
				}
			case <-ctx.Done():
				panic("missing QPACK acknowledgement")
			}
		}
		for {
			typ, data, e := readFrame(stream)
			if e != nil {
				if entry.Bytes < 65537 {
					panic(e)
				}
				var reset *quic.StreamError
				switch {
				case e == io.EOF:
					entry.End = "fin"
				case errors.As(e, &reset) && reset.Remote:
					entry.End = fmt.Sprintf("reset:%d", reset.ErrorCode)
				default:
					panic(e)
				}
				break
			}
			if typ == 0 {
				entry.Bytes += len(data)
				_, e = stream.Write(frame(0, data))
				must(e)
			}
		}
		_ = stream.Close() // Cronet Close cancels its read half after consuming the echo.
		appendCapture(entry)
	}
	// Record FIN and explicit resets separately; timeouts/truncated frames fail.
	mu.Lock()
	summary := map[string]any{"phase": "complete", "requests": 2, "streams": streams, "dynamic_qpack": dynamic, "informational_responses": informational, "decoder_feedback": feedback}
	data, e := json.MarshalIndent(summary, "", "  ")
	must(e)
	mu.Unlock()
	must(os.WriteFile(filepath.Join(output, "capture.json"), data, 0600))
	must(json.NewEncoder(os.Stdout).Encode(summary))
	// Keep the endpoint alive until the client consumes the final FIN and
	// releases its session; process exit must not race QUIC's send queue.
	select {
	case <-conn.Context().Done():
	case <-ctx.Done():
		panic("client did not release the completed capture session")
	}
}
