package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

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
	// Check for RELAY_PRIVATE_KEY env var (Base64 encoded)
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

	// Generate new key and print Base64 for user to save
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
	log.Println("To keep the same Peer ID after restart,")
	log.Println("add this environment variable in Render:")
	log.Println("")
	log.Println("RELAY_PRIVATE_KEY=" + keyB64)
	log.Println("========================================")

	return priv, nil
}

func main() {
	log.Println("Starting libp2p relay...")

	publicDNS := os.Getenv("RENDER_EXTERNAL_URL")
	if publicDNS == "" {
		publicDNS = "relay-torrentium-pj9h.onrender.com"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "443"
	}

	privKey, err := getPrivateKey()
	if err != nil {
		log.Fatalf("Failed to get private key: %v", err)
	}

	listenAddr := fmt.Sprintf("/ip4/0.0.0.0/tcp/%s/ws", port)
	h, err := libp2p.New(
		libp2p.Identity(privKey),
		libp2p.ListenAddrStrings(listenAddr),
		libp2p.Security(noise.ID, noise.New),
		libp2p.Transport(ws.New),
		libp2p.AddrsFactory(func(addrs []ma.Multiaddr) []ma.Multiaddr {
			maddr, _ := ma.NewMultiaddr(fmt.Sprintf("/dns4/%s/tcp/%s/wss", publicDNS, port))
			return []ma.Multiaddr{maddr}
		}),
	)
	if err != nil {
		log.Fatalf("Failed to create libp2p host: %v", err)
	}

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

	http.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		json.NewEncoder(w).Encode(relayInfo)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	log.Println("Relay started successfully")
	log.Printf("Peer ID: %s", h.ID())
	for _, addr := range h.Addrs() {
		log.Printf("Listening on: %s/p2p/%s", addr, h.ID())
	}
	log.Printf("Relay info URL: https://%s/info", publicDNS)

	select {}
}
