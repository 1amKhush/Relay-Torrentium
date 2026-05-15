package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	relayv2 "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"
	ws "github.com/libp2p/go-libp2p/p2p/transport/websocket"
	ma "github.com/multiformats/go-multiaddr"
)

type RelayInfo struct {
	PeerID     string   `json:"peer_id"`
	Multiaddrs []string `json:"multiaddrs"`
}

type NotifyBundle struct{}

const (
	defaultPublicHost = "relay-torrentium-pj9h.onrender.com"
	defaultHTTPPort   = "10000"
	relayListenAddr   = "/ip4/0.0.0.0/tcp/9000/ws"
)

var startTime = time.Now()

func (nb *NotifyBundle) Listen(n network.Network, a ma.Multiaddr)      {}
func (nb *NotifyBundle) ListenClose(n network.Network, a ma.Multiaddr) {}
func (nb *NotifyBundle) Connected(n network.Network, c network.Conn) {
	log.Printf("[connected] peer=%s", c.RemotePeer().String())
}
func (nb *NotifyBundle) Disconnected(n network.Network, c network.Conn) {
	log.Printf("[disconnected] peer=%s", c.RemotePeer().String())
}
func (nb *NotifyBundle) OpenedStream(net network.Network, stream network.Stream) {}
func (nb *NotifyBundle) ClosedStream(net network.Network, stream network.Stream) {}

func getPrivateKey() (crypto.PrivKey, error) {
	keyB64 := os.Getenv("RELAY_PRIVATE_KEY")
	if keyB64 != "" {
		keyBytes, err := base64.StdEncoding.DecodeString(keyB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode RELAY_PRIVATE_KEY: %w", err)
		}
		priv, err := crypto.UnmarshalPrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
		}
		log.Println("Loaded private key from RELAY_PRIVATE_KEY env var")
		return priv, nil
	}

	log.Println("No RELAY_PRIVATE_KEY found, generating new key...")
	priv, _, err := crypto.GenerateKeyPairWithReader(crypto.Ed25519, 2048, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	keyBytes, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key: %w", err)
	}

	keyB64 = base64.StdEncoding.EncodeToString(keyBytes)
	log.Println("========================================")
	log.Println("NEW PRIVATE KEY GENERATED!")
	log.Println("Add this env var in Render to keep same Peer ID:")
	log.Println("")
	log.Printf("RELAY_PRIVATE_KEY=%s", keyB64)
	log.Println("========================================")

	return priv, nil
}

func publicHostFromEnv(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultPublicHost
	}

	if strings.Contains(value, "://") {
		if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
			return parsed.Hostname()
		}
	}

	value = strings.TrimPrefix(value, "//")
	if slash := strings.IndexByte(value, '/'); slash >= 0 {
		value = value[:slash]
	}

	value = strings.TrimSuffix(value, "/")
	if host, _, found := strings.Cut(value, ":"); found {
		value = host
	}
	if value == "" {
		return defaultPublicHost
	}

	return value
}

func startSelfPing(ctx context.Context, publicURL string) {
	interval := 10 * time.Minute
	retryDelay := 30 * time.Second
	maxRetries := 3
	client := &http.Client{Timeout: 10 * time.Second}
	healthURL := fmt.Sprintf("https://%s/health", publicURL)

	log.Printf("[keep-alive] Self-ping enabled → %s every %v", healthURL, interval)

	select {
	case <-time.After(1 * time.Minute):
	case <-ctx.Done():
		return
	}

	for {
		success := false
		for attempt := 1; attempt <= maxRetries; attempt++ {
			resp, err := client.Get(healthURL)
			if err != nil {
				log.Printf("[keep-alive] Ping attempt %d/%d FAILED: %v", attempt, maxRetries, err)
			} else {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					log.Printf("[keep-alive] Ping OK (attempt %d)", attempt)
					success = true
					break
				}
				log.Printf("[keep-alive] Ping attempt %d/%d got status %d", attempt, maxRetries, resp.StatusCode)
			}

			if attempt < maxRetries {
				select {
				case <-time.After(retryDelay):
				case <-ctx.Done():
					return
				}
			}
		}

		if !success {
			log.Println("[keep-alive] WARNING: All ping attempts failed this cycle")
		}

		select {
		case <-time.After(interval):
		case <-ctx.Done():
			log.Println("[keep-alive] Self-ping stopped (context cancelled)")
			return
		}
	}
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutdown signal received...")
		cancel()
	}()

	log.Println("Starting libp2p relay...")

	publicHost := publicHostFromEnv(os.Getenv("RENDER_EXTERNAL_URL"))

	port := os.Getenv("PORT")
	if port == "" {
		port = defaultHTTPPort
	}

	privKey, err := getPrivateKey()
	if err != nil {
		log.Fatalf("Failed to get private key: %v", err)
	}

	advertisedAddr, err := ma.NewMultiaddr(fmt.Sprintf("/dns4/%s/tcp/443/wss", publicHost))
	if err != nil {
		log.Fatalf("Failed to build advertised relay address: %v", err)
	}

	h, err := libp2p.New(
		libp2p.Identity(privKey),
		libp2p.ListenAddrStrings(relayListenAddr),
		libp2p.Security(noise.ID, noise.New),
		libp2p.Transport(ws.New),
		libp2p.AddrsFactory(func(addrs []ma.Multiaddr) []ma.Multiaddr {
			return []ma.Multiaddr{advertisedAddr}
		}),
	)
	if err != nil {
		log.Fatalf("Failed to create libp2p host: %v", err)
	}
	defer h.Close()

	_, err = relayv2.New(h)
	if err != nil {
		log.Fatalf("Failed to enable relay v2: %v", err)
	}

	h.Network().Notify(&NotifyBundle{})

	relayInfo := RelayInfo{
		PeerID:     h.ID().String(),
		Multiaddrs: make([]string, 0),
	}
	for _, addr := range h.Addrs() {
		relayInfo.Multiaddrs = append(relayInfo.Multiaddrs, fmt.Sprintf("%s/p2p/%s", addr, h.ID()))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(relayInfo)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      "ok",
			"uptime":      time.Since(startTime).String(),
			"peers":       len(h.Network().Peers()),
			"connections": len(h.Network().Conns()),
			"timestamp":   time.Now().Format(time.RFC3339),
		})
	})

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	log.Println("Relay started successfully")
	log.Printf("Peer ID: %s", h.ID())
	log.Printf("WebSocket listening internally on port 9000")
	log.Printf("HTTP /info endpoint on port %s", port)

	go startSelfPing(ctx, publicHost)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP server failed: %v", err)
	}
}
