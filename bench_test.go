package main

// Benchmarks for sshmux's two hot paths: steady-state packet proxying and
// connection setup. They are self-contained -- the upstream SSH server and the
// auth API both run in-process -- so no external sshd is required:
//
//	go test -run XXX -bench . -benchtime 2s -count 10 .
//
// These were written to evaluate whether a GOAMD64=v3 build is worthwhile. It
// is not: the per-byte work is AES-NI/AVX2 assembly that x/crypto and the
// standard library already select at runtime via CPU feature detection, so
// raising GOAMD64 leaves it byte-for-byte identical. Measured across v1/v2/v3/
// v4 no benchmark here moves outside its own noise band.
//
// The one result worth acting on is BenchmarkChaCha20Core: x/crypto/chacha20
// ships no amd64 assembly, so chacha20-poly1305@openssh.com -- what OpenSSH
// clients pick by default -- runs its stream cipher in pure Go and proxies at
// roughly two thirds the throughput of aes128-gcm@openssh.com.

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"testing"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/ssh"
)

// benchUpstream runs an in-process SSH server that accepts any authentication
// and discards everything written to its channels.
func benchUpstream(b *testing.B, hostKey ssh.Signer, ciphers []string) string {
	config := &ssh.ServerConfig{
		NoClientAuth:      true,
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return &ssh.Permissions{}, nil },
		PasswordCallback:  func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return &ssh.Permissions{}, nil },
	}
	config.Ciphers = ciphers
	config.AddHostKey(hostKey)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for newChan := range chans {
					ch, chReqs, err := newChan.Accept()
					if err != nil {
						return
					}
					go func() {
						for req := range chReqs {
							if req.WantReply {
								req.Reply(true, nil)
							}
						}
					}()
					go func() {
						defer ch.Close()
						io.Copy(io.Discard, ch)
					}()
				}
			}()
		}
	}()
	return listener.Addr().String()
}

// benchAuthAPI runs the legacy auth API, pointing every user at upstreamAddr.
func benchAuthAPI(b *testing.B, upstreamAddr string, privateKey []byte) string {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { listener.Close() })

	mux := http.NewServeMux()
	mux.HandleFunc("/ssh", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		res := map[string]any{
			"status":      "ok",
			"vmid":        1141919,
			"address":     upstreamAddr,
			"private_key": string(privateKey),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(res)
	})
	go http.Serve(listener, mux)
	return listener.Addr().String()
}

// benchSSHMux starts an sshmux instance proxying to an in-process upstream.
func benchSSHMux(b *testing.B, ciphers []string) (addr string, clientKey ssh.Signer) {
	privateKey, err := os.ReadFile("fixtures/ssh_id_rsa")
	if err != nil {
		b.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		b.Fatal(err)
	}
	hostKeyPEM, err := os.ReadFile("fixtures/ssh_host_ed25519_key")
	if err != nil {
		b.Fatal(err)
	}
	hostKey, err := ssh.ParsePrivateKey(hostKeyPEM)
	if err != nil {
		b.Fatal(err)
	}

	upstreamAddr := benchUpstream(b, hostKey, ciphers)
	apiAddr := benchAuthAPI(b, upstreamAddr, privateKey)

	// Reserve a port for sshmux, then hand it over (Server.Start listens itself).
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	muxAddr := probe.Addr().String()
	probe.Close()

	server, err := makeServer(Config{
		Address: muxAddr,
		SSH: SSHConfig{
			HostKeys: []SSHKeyConfig{{Content: string(hostKeyPEM)}},
		},
		Auth: AuthConfig{
			Endpoint: fmt.Sprintf("http://%s/ssh", apiAddr),
			Version:  "legacy",
		},
	})
	if err != nil {
		b.Fatal(err)
	}
	server.SSHConfig.Ciphers = ciphers
	if err := server.Start(); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(server.Shutdown)

	// sshmux logs a line per torn-down session; silence it for the benchmark.
	log.SetOutput(io.Discard)
	b.Cleanup(func() { log.SetOutput(os.Stderr) })

	return muxAddr, signer
}

func benchDial(b *testing.B, addr string, key ssh.Signer, ciphers []string) *ssh.Client {
	config := &ssh.ClientConfig{
		User:            "bench",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	config.Ciphers = ciphers
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		b.Fatal(err)
	}
	return client
}

var benchCiphers = []struct {
	name    string
	ciphers []string
}{
	{"aes128-gcm", []string{"aes128-gcm@openssh.com"}},
	{"chacha20-poly1305", []string{"chacha20-poly1305@openssh.com"}},
	{"aes256-ctr", []string{"aes256-ctr"}},
}

// BenchmarkPipeThroughput measures steady-state proxying: every byte is
// decrypted from the downstream connection and re-encrypted for the upstream.
func BenchmarkPipeThroughput(b *testing.B) {
	for _, c := range benchCiphers {
		b.Run(c.name, func(b *testing.B) {
			addr, key := benchSSHMux(b, c.ciphers)
			client := benchDial(b, addr, key, c.ciphers)
			defer client.Close()

			session, err := client.NewSession()
			if err != nil {
				b.Fatal(err)
			}
			defer session.Close()
			stdin, err := session.StdinPipe()
			if err != nil {
				b.Fatal(err)
			}
			if err := session.Shell(); err != nil {
				b.Fatal(err)
			}

			const size = 1 << 20
			buf := make([]byte, size)
			b.SetBytes(size)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := stdin.Write(buf); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
		})
	}
}

// BenchmarkHandshake measures connection setup: key exchange and signatures on
// both legs, plus the auth round trip.
func BenchmarkHandshake(b *testing.B) {
	addr, key := benchSSHMux(b, nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client := benchDial(b, addr, key, nil)
		client.Close()
	}
}

// BenchmarkChaCha20Core measures the ChaCha20 stream cipher in isolation. On
// amd64 x/crypto/chacha20 has no assembly implementation, so this is pure Go
// and is the one part of the per-byte path whose codegen GOAMD64 can change.
func BenchmarkChaCha20Core(b *testing.B) {
	key := make([]byte, chacha20.KeySize)
	nonce := make([]byte, chacha20.NonceSize)
	buf := make([]byte, 32*1024)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
		if err != nil {
			b.Fatal(err)
		}
		c.XORKeyStream(buf, buf)
	}
}

// BenchmarkChaCha20Poly1305AEAD measures the RFC 8439 AEAD, which does have
// amd64 AVX2 assembly. Note that chacha20-poly1305@openssh.com does not use it:
// crypto/ssh composes chacha20 and poly1305 itself, so SSH gets the pure-Go
// ChaCha20 core benchmarked above.
func BenchmarkChaCha20Poly1305AEAD(b *testing.B) {
	aead, err := chacha20poly1305.New(make([]byte, chacha20poly1305.KeySize))
	if err != nil {
		b.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	buf := make([]byte, 32*1024)
	dst := make([]byte, 0, len(buf)+aead.Overhead())
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aead.Seal(dst[:0], nonce, buf, nil)
	}
}

// BenchmarkAESGCMCore is the control: AES-GCM is hand-written assembly selected
// by runtime CPU detection, so GOAMD64 must not change it.
func BenchmarkAESGCMCore(b *testing.B) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		b.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	buf := make([]byte, 32*1024)
	dst := make([]byte, 0, len(buf)+aead.Overhead())
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aead.Seal(dst[:0], nonce, buf, nil)
	}
}
