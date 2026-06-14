package db

import (
    "database/sql"
    "fmt"
    "time"

    _ "modernc.org/sqlite"
)

type DB struct{ conn *sql.DB }

type Row struct {
    ID      int64
    SrcIP   string
    DstIP   string
    Proto   string
    Size    int
    Flagged bool
    CapturedAt time.Time
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
    _, err := c.Exec(`
        CREATE TABLE IF NOT EXISTS packets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip      TEXT    NOT NULL,
            dst_ip      TEXT    NOT NULL,
            proto       TEXT    NOT NULL,
            size        INTEGER NOT NULL,
            flagged     INTEGER NOT NULL DEFAULT 0,
            captured_at DATETIME NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_packets_captured_at ON packets(captured_at);
        CREATE INDEX IF NOT EXISTS idx_packets_proto       ON packets(proto);
    `)
    return err
}

func (d *DB) Insert(r Row) error {
    _, err := d.conn.Exec(
        `INSERT INTO packets (src_ip,dst_ip,proto,size,flagged,captured_at)
         VALUES (?,?,?,?,?,?)`,
        r.SrcIP, r.DstIP, r.Proto, r.Size, boolInt(r.Flagged), r.CapturedAt,
    )
    return err
}

// QueryRecent returns the most recent `limit` rows (newest first).
func (d *DB) QueryRecent(limit int) ([]Row, error) {
    rows, err := d.conn.Query(
        `SELECT id,src_ip,dst_ip,proto,size,flagged,captured_at
         FROM packets ORDER BY id DESC LIMIT ?`, limit,
    )
    if err != nil { return nil, err }
    defer rows.Close()
    return scanRows(rows)
}

// QueryByProto returns rows for a given protocol, newest first.
func (d *DB) QueryByProto(proto string, limit int) ([]Row, error) {
    rows, err := d.conn.Query(
        `SELECT id,src_ip,dst_ip,proto,size,flagged,captured_at
         FROM packets WHERE proto=? ORDER BY id DESC LIMIT ?`, proto, limit,
    )
    if err != nil { return nil, err }
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
        if err := rows.Scan(&r.ID,&r.SrcIP,&r.DstIP,&r.Proto,&r.Size,&flagged,&r.CapturedAt); err != nil {
            return nil, err
        }
        r.Flagged = flagged == 1
        out = append(out, r)
    }
    return out, rows.Err()
}

func boolInt(b bool) int {
    if b { return 1 }
    return 0
}