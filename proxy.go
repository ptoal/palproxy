package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v2"
)

// Configuration struct to match the YAML
type Config struct {
	Proxies     []ProxyConfig `yaml:"proxies"`
	WebhookURL  string        `yaml:"webhookURL"`
	IdleTimeout int           `yaml:"idleTimeout"` // Idle timeout in seconds
	SecretKey   string        `yaml:"secretKey"`
	AuthToken   string        `yaml:"authToken"`
}

type ProxyConfig struct {
	ListenAddr  string `yaml:"listenAddr"`
	ForwardAddr string `yaml:"forwardAddr"`
}

// Struct for webhook payload
type WebhookEvent struct {
	Event     string `json:"event"`
	Timestamp string `json:"timestamp"`
}

var (
	// Mutex for safe access to connection state
	mu sync.Mutex
	// Tracks the last time a packet was forwarded
	lastPacketTime time.Time
	// Indicates if a "Traffic Detected" event was already sent
	trafficDetected bool
)

// Read and parse the YAML configuration file
func readConfig(configPath string) (*Config, error) {
	fmt.Println("Reading configuration...")
	configFile, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var config Config
	err = yaml.Unmarshal(configFile, &config)
	if err != nil {
		return nil, err
	}
	fmt.Println("Configuration loaded successfully.")
	return &config, nil
}

// Function to send webhook
func sendWebhook(url, event string, secretKey string, authToken string) {
	fmt.Printf("Sending webhook: %s\n", event)
	payload := WebhookEvent{
		Event:     event,
		Timestamp: time.Now().Format(time.RFC3339),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("Error marshalling webhook payload:", err)
		return
	}
	// Compute HMAC SHA-256 signature of the payload
	hmacHash := hmac.New(sha256.New, []byte(secretKey))
	_, err = hmacHash.Write(payloadBytes)
	if err != nil {
		fmt.Println("Error computing HMAC signature:", err)
		return
	}
	signature := hex.EncodeToString(hmacHash.Sum(nil))

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return
	}

	// Set the content type and authentication headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("x-hub-signature-256", signature)

	// Execute the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending webhook:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Println("Webhook sent successfully.")
	} else {
		fmt.Println("Webhook failed with status code:", resp.StatusCode)
	}
}

// Function to handle idle detection
func handleIdleDetection(config *Config) {
	ticker := time.NewTicker(time.Duration(config.IdleTimeout) * time.Second)
	for {
		<-ticker.C
		mu.Lock()
		if trafficDetected && time.Since(lastPacketTime) >= time.Duration(config.IdleTimeout)*time.Second {
			sendWebhook(config.WebhookURL, "Traffic Stopped", config.SecretKey, config.AuthToken)
			trafficDetected = false // Reset state
		}
		mu.Unlock()
	}
}

func startProxy(proxyConfig ProxyConfig, webhookURL string, idleTimeout int, secretKey string, authToken string) {
	srcAddr, err := net.ResolveUDPAddr("udp", proxyConfig.ListenAddr)
	if err != nil {
		fmt.Println("Error resolving source address:", err)
		return
	}

	dstAddr, err := net.ResolveUDPAddr("udp", proxyConfig.ForwardAddr)
	if err != nil {
		fmt.Println("Error resolving destination address:", err)
		return
	}

	srcConn, err := net.ListenUDP("udp", srcAddr)
	if err != nil {
		fmt.Println("Error listening on source address:", err)
		return
	}
	defer srcConn.Close()

	dstConn, err := net.DialUDP("udp", nil, dstAddr)
	if err != nil {
		fmt.Println("Error dialing destination address:", err)
		return
	}
	defer dstConn.Close()

	fmt.Printf("Proxying from %s to %s\n", proxyConfig.ListenAddr, proxyConfig.ForwardAddr)

	buffer := make([]byte, 4096)
	for {
		n, _, err := srcConn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Error reading from UDP:", err)
			continue
		}
		if n > 0 {
			// Forward packet
			_, err := dstConn.Write(buffer[:n])
			if err != nil {
				fmt.Println("Error forwarding packet:", err)
			}

			mu.Lock()
			if !trafficDetected {
				sendWebhook(webhookURL, "Traffic Detected", secretKey, authToken)
				trafficDetected = true
			}
			lastPacketTime = time.Now()
			mu.Unlock()

		}
	}
}

func main() {
	fmt.Println("Starting UDP proxy application...")
	config, err := readConfig("config.yaml")
	if err != nil {
		fmt.Println("Failed to read configuration:", err)
		return
	}

	for _, proxyConfig := range config.Proxies {
		go startProxy(proxyConfig, config.WebhookURL, config.IdleTimeout, config.SecretKey, config.AuthToken)
	}

	go handleIdleDetection(config)

	// Prevent the main goroutine from exiting
	select {}
}
