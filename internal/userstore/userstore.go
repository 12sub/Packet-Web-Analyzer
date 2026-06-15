package userstore

import (
    "database/sql"
    "fmt"
    "time"

    _ "modernc.org/sqlite"
)

type User struct {
    ID           int64
    Username     string
    PasswordHash string
    Role         string
    CreatedAt    time.Time
}

type Store struct{ conn *sql.DB }

func Open(path string) (*Store, error) {
    conn, err := sql.Open("sqlite", path)
    if err != nil {
        return nil, fmt.Errorf("userstore open: %w", err)
    }
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
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER  PRIMARY KEY AUTOINCREMENT,
            username      TEXT     NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT     NOT NULL,
            role          TEXT     NOT NULL CHECK(role IN ('user','editor','admin')),
            created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    `)
    return err
}

func (s *Store) Create(username, passwordHash, role string) (int64, error) {
    res, err := s.conn.Exec(
        `INSERT INTO users (username, password_hash, role) VALUES (?,?,?)`,
        username, passwordHash, role,
    )
    if err != nil {
        return 0, err
    }
    return res.LastInsertId()
}

func (s *Store) GetByUsername(username string) (*User, error) {
    row := s.conn.QueryRow(
        `SELECT id,username,password_hash,role,created_at FROM users WHERE username=?`, username,
    )
    return scanUser(row)
}

func (s *Store) GetByID(id int64) (*User, error) {
    row := s.conn.QueryRow(
        `SELECT id,username,password_hash,role,created_at FROM users WHERE id=?`, id,
    )
    return scanUser(row)
}

func (s *Store) List() ([]User, error) {
    rows, err := s.conn.Query(
        `SELECT id,username,password_hash,role,created_at FROM users ORDER BY id`,
    )
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    var users []User
    for rows.Next() {
        u, err := scanUser(rows)
        if err != nil {
            return nil, err
        }
        users = append(users, *u)
    }
    return users, rows.Err()
}

func (s *Store) UpdateRole(id int64, role string) error {
    _, err := s.conn.Exec(`UPDATE users SET role=? WHERE id=?`, role, id)
    return err
}

func (s *Store) UpdatePassword(id int64, hash string) error {
    _, err := s.conn.Exec(`UPDATE users SET password_hash=? WHERE id=?`, hash, id)
    return err
}

func (s *Store) Delete(id int64) error {
    _, err := s.conn.Exec(`DELETE FROM users WHERE id=?`, id)
    return err
}

func (s *Store) Count() (int64, error) {
    var n int64
    return n, s.conn.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
}

type scanner interface{ Scan(...any) error }

func scanUser(s scanner) (*User, error) {
    var u User
    err := s.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.CreatedAt)
    if err != nil {
        return nil, err
    }
    return &u, nil
}