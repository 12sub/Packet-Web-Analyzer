package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"example.com/packet-analyser/internal/db"
	"example.com/packet-analyser/internal/stats"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const ExportDir = "./exports"

type FileInfo struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size_bytes"`
	Kind    string    `json:"kind"` // "pcap" | "csv" | "json"
	Created time.Time `json:"created"`
}

type Exporter struct {
	mu        sync.Mutex
	pcapFile  *os.File
	pcapW     *pcapgo.Writer
	recording bool
}

func New() (*Exporter, error) {
	if err := os.MkdirAll(ExportDir, 0755); err != nil {
		return nil, fmt.Errorf("create export dir: %w", err)
	}
	return &Exporter{}, nil
}

func (e *Exporter) StartPCAP() (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.recording {
		return "", fmt.Errorf("recording already active")
	}
	name := fmt.Sprintf("capture_%s.pcap", timestamp())
	path := filepath.Join(ExportDir, name)
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		f.Close()
		return "", err
	}
	e.pcapFile = f
	e.pcapW = w
	e.recording = true
	return name, nil
}

func (e *Exporter) StopPCAP() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.recording {
		return fmt.Errorf("no active recording")
	}
	err := e.pcapFile.Close()
	e.pcapFile = nil
	e.pcapW = nil
	e.recording = false
	return err
}

func (e *Exporter) WritePacket(p stats.Packet) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.recording {
		return
	}
	ci := gopacket.CaptureInfo{
		Timestamp:     p.Time,
		CaptureLength: p.Size,
		Length:        p.Size,
	}
	dummy := make([]byte, p.Size)
	e.pcapW.WritePacket(ci, dummy)
}

func (e *Exporter) IsRecording() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.recording
}

func ExportCSV(database *db.DB, limit int) (string, error) {
	rows, err := database.QueryRecent(limit)
	if err != nil {
		return "", err
	}
	name := fmt.Sprintf("packets_%s.csv", timestamp())
	f, err := os.Create(filepath.Join(ExportDir, name))
	if err != nil {
		return "", err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	w.Write([]string{"id", "src_ip", "dst_ip", "proto", "size", "flagged", "captured_at"})
	for _, r := range rows {
		w.Write([]string{
			fmt.Sprint(r.ID), r.SrcIP, r.DstIP, r.Proto,
			fmt.Sprint(r.Size), fmt.Sprint(r.Flagged),
			r.CapturedAt.Format(time.RFC3339),
		})
	}
	w.Flush()
	return name, w.Error()
}

func ExportJSON(snap stats.Snapshot) (string, error) {
	name := fmt.Sprintf("stats_%s.json", timestamp())
	f, err := os.Create(filepath.Join(ExportDir, name))
	if err != nil {
		return "", err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return name, enc.Encode(snap)
}

func ListFiles() ([]FileInfo, error) {
	entries, err := os.ReadDir(ExportDir)
	if err != nil {
		return nil, err
	}
	var files []FileInfo
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if e.IsDir() {
			continue
		}
		info, _ := e.Info()
		ext := filepath.Ext(e.Name())
		kind := map[string]string{".pcap": "pcap", ".csv": "csv", ".json": "json"}[ext]
		if kind == "" {
			continue
		}
		files = append(files, FileInfo{
			Name:    e.Name(),
			Size:    info.Size(),
			Kind:    kind,
			Created: info.ModTime(),
		})
	}
	return files, nil
}

func DeleteFile(name string) error {
	clean := filepath.Base(name)
	return os.Remove(filepath.Join(ExportDir, clean))
}

func timestamp() string {
	return time.Now().Format("20060102_150405")
}