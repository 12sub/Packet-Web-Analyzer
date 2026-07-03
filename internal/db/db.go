package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct{ conn *sql.DB }

type Row struct {
	ID          int64
	SrcIP       string
	DstIP       string
	Proto       string
	Size        int
	Flagged     bool
	CapturedAt  time.Time
	SrcMAC      string
	DstMAC      string
	SrcVendor   string
	DstVendor   string
	TTL         int
	SrcGeo      string
	DstGeo      string
	SrcHost     string
	DstHost     string
	Quarantined bool
}

func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("sqlite open: %w", err)
	}
	if err := migrate(conn); err != nil {
		return nil, err
	}
	// tune for write throughput
	conn.SetMaxOpenConns(1)
	conn.Exec("PRAGMA journal_mode=WAL;")
	conn.Exec("PRAGMA synchronous=NORMAL;")
	return &DB{conn: conn}, nil
}

func (d *DB) Close() { d.conn.Close() }

func migrate(c *sql.DB) error {
	// Step 1: Create base table (without quarantined — will add via ALTER)
	_, err := c.Exec(`
		CREATE TABLE IF NOT EXISTS packets (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			src_ip      TEXT    NOT NULL,
			dst_ip      TEXT    NOT NULL,
			proto       TEXT    NOT NULL,
			size        INTEGER NOT NULL,
			flagged     INTEGER NOT NULL DEFAULT 0,
			captured_at DATETIME NOT NULL,
			src_mac     TEXT,
			dst_mac     TEXT,
			src_vendor  TEXT,
			dst_vendor  TEXT,
			ttl         INTEGER,
			src_geo     TEXT,
			dst_geo     TEXT,
			src_host    TEXT,
			dst_host    TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_packets_captured_at ON packets(captured_at);
		CREATE INDEX IF NOT EXISTS idx_packets_proto       ON packets(proto);
		CREATE INDEX IF NOT EXISTS idx_packets_flagged     ON packets(flagged);
	`)
	if err != nil {
		return err
	}

	// Step 2: Add columns one by one (best-effort, ignore "duplicate column" errors)
	addColumns(c)

	// Step 3: Create quarantine table
	_, err = c.Exec(`
		CREATE TABLE IF NOT EXISTS quarantine (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			packet_id      INTEGER NOT NULL,
			src_ip         TEXT    NOT NULL,
			dst_ip         TEXT    NOT NULL,
			proto          TEXT    NOT NULL,
			size           INTEGER NOT NULL,
			captured_at    DATETIME NOT NULL,
			src_mac        TEXT,
			dst_mac        TEXT,
			src_vendor     TEXT,
			dst_vendor     TEXT,
			ttl            INTEGER,
			src_geo        TEXT,
			dst_geo        TEXT,
			src_host       TEXT,
			dst_host       TEXT,
			quarantined_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			yara_rule      TEXT,
			FOREIGN KEY (packet_id) REFERENCES packets(id)
		);
		CREATE INDEX IF NOT EXISTS idx_packets_quarantined ON packets(quarantined);
	`)
	return err
}

// addColumns performs best-effort ALTER TABLE for databases created before
// certain columns existed. SQLite errors are ignored because:
// - "duplicate column name" → column already exists, that's fine
// - other errors → we'll log and continue
func addColumns(c *sql.DB) {
	cols := []string{
		"src_mac TEXT",
		"dst_mac TEXT",
		"src_vendor TEXT",
		"dst_vendor TEXT",
		"ttl INTEGER",
		"src_geo TEXT",
		"dst_geo TEXT",
		"src_host TEXT",
		"dst_host TEXT",
		// IMPORTANT: Must have DEFAULT when adding NOT NULL to existing table
		"quarantined INTEGER NOT NULL DEFAULT 0",
	}
	for _, col := range cols {
		// Using Exec directly — errors are ignored (column likely exists)
		c.Exec("ALTER TABLE packets ADD COLUMN " + col)
	}
}

func (d *DB) Insert(r Row) error {
	_, err := d.conn.Exec(
		`INSERT INTO packets (src_ip,dst_ip,proto,size,flagged,captured_at,quarantined,
		 src_mac,dst_mac,src_vendor,dst_vendor,ttl,src_geo,dst_geo,src_host,dst_host)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.SrcIP, r.DstIP, r.Proto, r.Size, boolInt(r.Flagged), r.CapturedAt, boolInt(r.Quarantined),
		r.SrcMAC, r.DstMAC, r.SrcVendor, r.DstVendor, r.TTL,
		r.SrcGeo, r.DstGeo, r.SrcHost, r.DstHost,
	)
	return err
}

func (d *DB) QueryFlagged(limit int) ([]Row, error) {
	rows, err := d.conn.Query(
		`SELECT id,src_ip,dst_ip,proto,size,flagged,captured_at,quarantined,
		 src_mac,dst_mac,src_vendor,dst_vendor,ttl,src_geo,dst_geo,src_host,dst_host
		 FROM packets WHERE flagged=1 ORDER BY id DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

func (d *DB) CountFlagged() (int64, error) {
	var n int64
	err := d.conn.QueryRow(`SELECT COUNT(*) FROM packets WHERE flagged=1`).Scan(&n)
	return n, err
}

func (d *DB) DeleteAllFlagged() (int64, error) {
	res, err := d.conn.Exec(`DELETE FROM packets WHERE flagged=1`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (d *DB) QuarantineFlagged() (int64, error) {
	tx, err := d.conn.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// Copy flagged to quarantine
	_, err = tx.Exec(`
		INSERT INTO quarantine (packet_id, src_ip, dst_ip, proto, size, captured_at,
		 src_mac, dst_mac, src_vendor, dst_vendor, ttl, src_geo, dst_geo, src_host, dst_host)
		SELECT id, src_ip, dst_ip, proto, size, captured_at,
		 src_mac, dst_mac, src_vendor, dst_vendor, ttl, src_geo, dst_geo, src_host, dst_host
		FROM packets WHERE flagged=1 AND quarantined=0
	`)
	if err != nil {
		return 0, err
	}

	// Mark as quarantined
	res, err := tx.Exec(`UPDATE packets SET quarantined=1 WHERE flagged=1 AND quarantined=0`)
	if err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (d *DB) QueryQuarantine(limit int) ([]Row, error) {
	rows, err := d.conn.Query(
		`SELECT packet_id,src_ip,dst_ip,proto,size,1,captured_at,1,
		 src_mac,dst_mac,src_vendor,dst_vendor,ttl,src_geo,dst_geo,src_host,dst_host
		 FROM quarantine ORDER BY quarantined_at DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

// ── YARA Rule Generation ───────────────────────────────────────────────────

func (d *DB) GenerateYaraRule() (string, error) {
	rows, err := d.conn.Query(
		`SELECT DISTINCT src_ip, dst_ip, proto, src_host, dst_host
		 FROM packets WHERE flagged=1`,
	)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var srcIPs, dstIPs, protos []string
	hostSet := make(map[string]bool)

	for rows.Next() {
		var srcIP, dstIP, proto, srcHost, dstHost string
		if err := rows.Scan(&srcIP, &dstIP, &proto, &srcHost, &dstHost); err != nil {
			continue
		}
		srcIPs = append(srcIPs, fmt.Sprintf(`        $src%d = "%s"`, len(srcIPs)+1, srcIP))
		dstIPs = append(dstIPs, fmt.Sprintf(`        $dst%d = "%s"`, len(dstIPs)+1, dstIP))
		protos = append(protos, fmt.Sprintf(`        $proto%d = "%s"`, len(protos)+1, proto))
		if srcHost != "" {
			hostSet[srcHost] = true
		}
		if dstHost != "" {
			hostSet[dstHost] = true
		}
	}

	var hostStrings []string
	i := 1
	for h := range hostSet {
		hostStrings = append(hostStrings, fmt.Sprintf(`        $host%d = "%s"`, i, h))
		i++
	}

	rule := fmt.Sprintf(`rule PacketAnalyzer_Flagged_Traffic {
    meta:
        description = "Auto-generated YARA rule from Packet Analyzer flagged traffic"
        author = "Packet Analyzer"
        date = "%s"
        version = "1.0"

    strings:
        // Source IPs
%s

        // Destination IPs
%s

        // Protocols
%s

        // Hostnames
%s

    condition:
        any of them
}`, time.Now().Format("2006-01-02"),
		joinStrings(srcIPs),
		joinStrings(dstIPs),
		joinStrings(protos),
		joinStrings(hostStrings))

	return rule, nil
}

func joinStrings(s []string) string {
	if len(s) == 0 {
		return "        // none"
	}
	result := ""
	for _, str := range s {
		result += str + "\n"
	}
	return result
}

// QueryRecent returns the most recent `limit` rows (newest first).
func (d *DB) QueryRecent(limit int) ([]Row, error) {
	rows, err := d.conn.Query(
		`SELECT id,src_ip,dst_ip,proto,size,flagged,captured_at,quarantined,
		 src_mac,dst_mac,src_vendor,dst_vendor,ttl,src_geo,dst_geo,src_host,dst_host
		 FROM packets ORDER BY id DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

// QueryByProto returns rows for a given protocol, newest first.
func (d *DB) QueryByProto(proto string, limit int) ([]Row, error) {
	rows, err := d.conn.Query(
		`SELECT id,src_ip,dst_ip,proto,size,flagged,captured_at,quarantined,
		 src_mac,dst_mac,src_vendor,dst_vendor,ttl,src_geo,dst_geo,src_host,dst_host
		 FROM packets WHERE proto=? ORDER BY id DESC LIMIT ?`, proto, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

// Count returns total rows stored.
func (d *DB) Count() (int64, error) {
	var n int64
	err := d.conn.QueryRow(`SELECT COUNT(*) FROM packets`).Scan(&n)
	return n, err
}

func scanRows(rows *sql.Rows) ([]Row, error) {
	var out []Row
	for rows.Next() {
		var r Row
		var flagged int
		var quarantined int
		if err := rows.Scan(&r.ID, &r.SrcIP, &r.DstIP, &r.Proto, &r.Size, &flagged, &r.CapturedAt, &quarantined,
			&r.SrcMAC, &r.DstMAC, &r.SrcVendor, &r.DstVendor, &r.TTL,
			&r.SrcGeo, &r.DstGeo, &r.SrcHost, &r.DstHost); err != nil {
			return nil, err
		}
		r.Flagged = flagged == 1
		r.Quarantined = quarantined == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}