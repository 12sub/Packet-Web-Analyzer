package alerts

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Rule represents a single alert configuration stored in the database.
type Rule struct {
	ID            int64
	Name          string
	Type          string // "traffic_spike", "ip_threshold", "anomaly"
	Target        string // IP address (used for ip_threshold)
	Threshold     int
	WindowSecs    int
	WebhookURL    string
	CooldownSecs  int
	LastTriggered time.Time
	Enabled       bool
}

// Store manages the SQLite database for alert rules.
type Store struct {
	conn *sql.DB
}

// Open initializes the alerts database and creates the table if it doesn't exist.
func Open(path string) (*Store, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("alerts open: %w", err)
	}
	
	// Optimize for SQLite
	conn.SetMaxOpenConns(1)
	conn.Exec("PRAGMA journal_mode=WAL;")
	
	if err := migrate(conn); err != nil {
		return nil, err
	}
	return &Store{conn: conn}, nil
}

func (s *Store) Close() { 
	s.conn.Close() 
}

// migrate creates the alert_rules table if it doesn't already exist.
func migrate(c *sql.DB) error {
	_, err := c.Exec(`
		CREATE TABLE IF NOT EXISTS alert_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			type TEXT NOT NULL,
			target TEXT,
			threshold INTEGER NOT NULL,
			window_secs INTEGER NOT NULL,
			webhook_url TEXT NOT NULL,
			cooldown_secs INTEGER NOT NULL DEFAULT 300,
			last_triggered DATETIME,
			enabled BOOLEAN NOT NULL DEFAULT 1
		);
	`)
	return err
}

// Create inserts a new alert rule into the database.
func (s *Store) Create(r Rule) error {
	res, err := s.conn.Exec(
		`INSERT INTO alert_rules (name, type, target, threshold, window_secs, webhook_url, cooldown_secs, enabled) 
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Name, r.Type, r.Target, r.Threshold, r.WindowSecs, r.WebhookURL, r.CooldownSecs, r.Enabled,
	)
	if err == nil {
		r.ID, _ = res.LastInsertId()
	}
	return err
}

// List retrieves all alert rules from the database.
func (s *Store) List() ([]Rule, error) {
	rows, err := s.conn.Query(`
		SELECT id, name, type, target, threshold, window_secs, webhook_url, cooldown_secs, last_triggered, enabled 
		FROM alert_rules
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []Rule
	for rows.Next() {
		var r Rule
		var lt sql.NullTime
		if err := rows.Scan(&r.ID, &r.Name, &r.Type, &r.Target, &r.Threshold, &r.WindowSecs, &r.WebhookURL, &r.CooldownSecs, &lt, &r.Enabled); err != nil {
			return nil, err
		}
		if lt.Valid { 
			r.LastTriggered = lt.Time 
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// Delete removes an alert rule by its ID.
func (s *Store) Delete(id int64) error {
	_, err := s.conn.Exec(`DELETE FROM alert_rules WHERE id = ?`, id)
	return err
}

// UpdateLastTriggered updates the timestamp of when a rule was last fired.
func (s *Store) UpdateLastTriggered(id int64) {
	s.conn.Exec(`UPDATE alert_rules SET last_triggered = ? WHERE id = ?`, time.Now(), id)
}