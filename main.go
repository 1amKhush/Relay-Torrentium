package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

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

func (nb *NotifyBundle) Listen(n network.Network, a ma.Multiaddr) {
	log.Printf("[notifiee] Listen: %s\n", a)
}

func (nb *NotifyBundle) ListenClose(n network.Network, a ma.Multiaddr) {
	log.Printf("[notifiee] ListenClose: %s\n", a)
}

func (nb *NotifyBundle) Connected(n network.Network, c network.Conn) {
	log.Printf("[notifiee] Connected: %s <-> %s  peer=%s\n",
		c.LocalMultiaddr(), c.RemoteMultiaddr(), c.RemotePeer().String())
}

func (nb *NotifyBundle) Disconnected(n network.Network, c network.Conn) {
	log.Printf("[notifiee] Disconnected: %s <-> %s  peer=%s\n",
		c.LocalMultiaddr(), c.RemoteMultiaddr(), c.RemotePeer().String())
}

func (nb *NotifyBundle) OpenedStream(net network.Network, stream network.Stream) {
	log.Printf("[notifiee] OpenedStream: from=%s to=%s protocol=%s\n",
		stream.Conn().LocalPeer().String(), stream.Conn().RemotePeer().String(), stream.Protocol())
}

func (nb *NotifyBundle) ClosedStream(net network.Network, stream network.Stream) {
	log.Printf("[notifiee] ClosedStream: from=%s to=%s protocol=%s\n",
		stream.Conn().LocalPeer().String(), stream.Conn().RemotePeer().String(), stream.Protocol())
}

func loadOrCreatePrivateKey(keyPath string) (crypto.PrivKey, error) {
	if data, err := os.ReadFile(keyPath); err == nil {
		priv, err := crypto.UnmarshalPrivateKey(data)
		if err == nil {
			log.Println("Loaded existing private key")
			return priv, nil
		}
		log.Printf("Failed to unmarshal key: %v", err)
	}

	priv, _, err := crypto.GenerateKeyPairWithReader(crypto.Ed25519, 2048, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	data, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		log.Printf("Could not create key directory: %v", err)
	} else if err := os.WriteFile(keyPath, data, 0600); err != nil {
		log.Printf("Could not save private key: %v", err)
	} else {
		log.Println("Generated and saved new private key")
	}

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

	keyPath := os.Getenv("KEY_PATH")
	if keyPath == "" {
		keyPath = "/data/relay_private_key"
	}

	privKey, err := loadOrCreatePrivateKey(keyPath)
	if err != nil {
		log.Fatalf("Failed to load/create private key: %v", err)
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
