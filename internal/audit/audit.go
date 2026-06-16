// internal/audit/audit.go
package audit

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Event represents a single audit log entry.
type Event struct {
	Timestamp time.Time
	UserID    int64
	Username  string
	Action    string
	Details   string
	IPAddress string
}

// Store manages the audit log database.
type Store struct {
	conn *sql.DB
}

// Open initializes the audit database and creates the table if it doesn't exist.
func Open(path string) (*Store, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("audit open: %w", err)
	}
	
	// Optimize for write-heavy workloads
	conn.SetMaxOpenConns(1)
	conn.Exec("PRAGMA journal_mode=WAL;")
	
	if err := migrate(conn); err != nil {
		return nil, err
	}
	return &Store{conn: conn}, nil
}

func (s *Store) Close() { s.conn.Close() }

func migrate(c *sql.DB) error {
	_, err := c.Exec(`
		CREATE TABLE IF NOT EXISTS audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			user_id INTEGER,
			username TEXT,
			action TEXT NOT NULL,
			details TEXT,
			ip_address TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
	`)
	return err
}

// Log inserts a new event into the database.
func (s *Store) Log(e Event) error {
	_, err := s.conn.Exec(
		`INSERT INTO audit_logs (timestamp, user_id, username, action, details, ip_address)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		e.Timestamp, e.UserID, e.Username, e.Action, e.Details, e.IPAddress,
	)
	return err
}

// Recent retrieves the most recent audit events.
func (s *Store) Recent(limit int) ([]Event, error) {
	rows, err := s.conn.Query(
		`SELECT timestamp, user_id, username, action, details, ip_address 
		 FROM audit_logs ORDER BY id DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.Timestamp, &e.UserID, &e.Username, &e.Action, &e.Details, &e.IPAddress); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}