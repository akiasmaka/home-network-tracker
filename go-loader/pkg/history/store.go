package history

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/akiasmaka/home-network-tracker/go-loader/pkg/tracker"
	_ "modernc.org/sqlite"
)

// DB wraps a SQLite database for persisting snapshots and connections.
type DB struct {
	db *sql.DB
	mu sync.Mutex
}

const schema = `
CREATE TABLE IF NOT EXISTS snapshots_raw (
	timestamp INTEGER PRIMARY KEY,
	summary   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots_1m (
	timestamp INTEGER PRIMARY KEY,
	summary   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots_5m (
	timestamp INTEGER PRIMARY KEY,
	summary   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS connections (
	key         BLOB    PRIMARY KEY,
	data        TEXT    NOT NULL,
	last_updated INTEGER NOT NULL
);
`

// OpenDB opens (or creates) a SQLite database at dbPath and applies the schema.
func OpenDB(dbPath string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)&_pragma=synchronous(normal)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// Single writer connection to avoid SQLITE_BUSY under concurrent access.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}

	return &DB{db: db}, nil
}

// Close closes the underlying database.
func (d *DB) Close() error {
	return d.db.Close()
}

// InsertSnapshot inserts a snapshot into the raw (1-second) table.
func (d *DB) InsertSnapshot(snap Snapshot) error {
	summaryJSON, err := json.Marshal(snap.Summary)
	if err != nil {
		return fmt.Errorf("marshal summary: %w", err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err = d.db.Exec(
		`INSERT OR REPLACE INTO snapshots_raw (timestamp, summary) VALUES (?, ?)`,
		snap.Timestamp, string(summaryJSON),
	)
	return err
}

// QuerySnapshots returns snapshots from the appropriate tier table for the
// given time range. It selects the tier based on the span between sinceMs and
// the current time:
//   - <= 1 hour → snapshots_raw  (1-second resolution)
//   - <= 24 hours → snapshots_1m (1-minute resolution)
//   - otherwise → snapshots_5m   (5-minute resolution)
func (d *DB) QuerySnapshots(sinceMs int64, nowMs int64) ([]Snapshot, error) {
	spanMs := nowMs - sinceMs

	const (
		oneHourMs = 60 * 60 * 1000
		oneDayMs  = 24 * 60 * 60 * 1000
	)

	queryRange := func(table string, startMs int64, endMs int64) ([]Snapshot, error) {
		if startMs > endMs {
			return []Snapshot{}, nil
		}
		rows, err := d.db.Query(
			fmt.Sprintf(`SELECT timestamp, summary FROM %s WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp ASC`, table),
			startMs,
			endMs,
		)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		var snapshots []Snapshot
		for rows.Next() {
			var s Snapshot
			var summaryJSON string
			if err := rows.Scan(&s.Timestamp, &summaryJSON); err != nil {
				return nil, err
			}
			if err := json.Unmarshal([]byte(summaryJSON), &s.Summary); err != nil {
				return nil, fmt.Errorf("unmarshal summary: %w", err)
			}
			snapshots = append(snapshots, s)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		if snapshots == nil {
			snapshots = []Snapshot{}
		}
		return snapshots, nil
	}

	maxInt64 := func(a int64, b int64) int64 {
		if a > b {
			return a
		}
		return b
	}

	var snapshots []Snapshot
	switch {
	case spanMs <= oneHourMs:
		return queryRange("snapshots_raw", sinceMs, nowMs)
	case spanMs <= oneDayMs:
		oneHourStart := nowMs - oneHourMs
		if sinceMs < oneHourStart {
			part, err := queryRange("snapshots_1m", sinceMs, oneHourStart)
			if err != nil {
				return nil, err
			}
			snapshots = append(snapshots, part...)
		}
		part, err := queryRange("snapshots_raw", maxInt64(sinceMs, oneHourStart), nowMs)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, part...)
	default:
		oneDayStart := nowMs - oneDayMs
		oneHourStart := nowMs - oneHourMs
		if sinceMs < oneDayStart {
			part, err := queryRange("snapshots_5m", sinceMs, oneDayStart)
			if err != nil {
				return nil, err
			}
			snapshots = append(snapshots, part...)
		}
		if maxInt64(sinceMs, oneDayStart) < oneHourStart {
			part, err := queryRange("snapshots_1m", maxInt64(sinceMs, oneDayStart), oneHourStart)
			if err != nil {
				return nil, err
			}
			snapshots = append(snapshots, part...)
		}
		part, err := queryRange("snapshots_raw", maxInt64(sinceMs, oneHourStart), nowMs)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, part...)
	}

	if snapshots == nil {
		snapshots = []Snapshot{}
	}
	return snapshots, nil
}

// Downsample aggregates raw snapshots older than 1 hour into 1-minute buckets,
// and 1-minute snapshots older than 24 hours into 5-minute buckets.
func (d *DB) Downsample(nowMs int64) error {
	const (
		oneHourMs = 60 * 60 * 1000
		oneDayMs  = 24 * 60 * 60 * 1000
		oneMinMs  = 60 * 1000
		fiveMinMs = 5 * 60 * 1000
	)

	d.mu.Lock()
	defer d.mu.Unlock()

	// --- raw → 1m ---
	rawCutoff := nowMs - oneHourMs
	if err := d.aggregate("snapshots_raw", "snapshots_1m", rawCutoff, oneMinMs); err != nil {
		return fmt.Errorf("downsample raw→1m: %w", err)
	}

	// --- 1m → 5m ---
	cutoff1m := nowMs - oneDayMs
	if err := d.aggregate("snapshots_1m", "snapshots_5m", cutoff1m, fiveMinMs); err != nil {
		return fmt.Errorf("downsample 1m→5m: %w", err)
	}

	return nil
}

// aggregate reads rows from srcTable with timestamp < cutoff, groups them into
// buckets of bucketMs width, averages/sums the summary fields, inserts the
// results into dstTable, and deletes the originals from srcTable.
func (d *DB) aggregate(srcTable, dstTable string, cutoff, bucketMs int64) error {
	query := fmt.Sprintf(
		`SELECT timestamp, summary FROM %s WHERE timestamp < ? ORDER BY timestamp ASC`,
		srcTable,
	)
	rows, err := d.db.Query(query, cutoff)
	if err != nil {
		return err
	}
	defer rows.Close()

	// Group by bucket.
	type bucket struct {
		ts        int64 // bucket key (floored timestamp)
		summaries []Summary
	}
	buckets := make(map[int64]*bucket)
	var bucketOrder []int64

	for rows.Next() {
		var ts int64
		var summaryJSON string
		if err := rows.Scan(&ts, &summaryJSON); err != nil {
			return err
		}
		var s Summary
		if err := json.Unmarshal([]byte(summaryJSON), &s); err != nil {
			return err
		}
		bKey := (ts / bucketMs) * bucketMs
		if _, ok := buckets[bKey]; !ok {
			buckets[bKey] = &bucket{ts: bKey}
			bucketOrder = append(bucketOrder, bKey)
		}
		buckets[bKey].summaries = append(buckets[bKey].summaries, s)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(buckets) == 0 {
		return nil
	}

	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	insertStmt, err := tx.Prepare(
		fmt.Sprintf(`INSERT OR REPLACE INTO %s (timestamp, summary) VALUES (?, ?)`, dstTable),
	)
	if err != nil {
		return err
	}
	defer insertStmt.Close()

	for _, bKey := range bucketOrder {
		b := buckets[bKey]
		merged := mergeSummaries(b.summaries)
		data, err := json.Marshal(merged)
		if err != nil {
			return err
		}
		if _, err := insertStmt.Exec(b.ts, string(data)); err != nil {
			return err
		}
	}

	// Delete aggregated rows from source.
	if _, err := tx.Exec(
		fmt.Sprintf(`DELETE FROM %s WHERE timestamp < ?`, srcTable),
		cutoff,
	); err != nil {
		return err
	}

	return tx.Commit()
}

// Prune deletes data older than the retention windows:
//   - snapshots_raw: older than 1 hour
//   - snapshots_1m:  older than 24 hours
//   - snapshots_5m:  older than 7 days
func (d *DB) Prune(nowMs int64, retentionMs int64) error {
	const (
		oneHourMs = 60 * 60 * 1000
		oneDayMs  = 24 * 60 * 60 * 1000
	)

	d.mu.Lock()
	defer d.mu.Unlock()

	if _, err := d.db.Exec(`DELETE FROM snapshots_raw WHERE timestamp < ?`, nowMs-oneHourMs); err != nil {
		return err
	}
	if _, err := d.db.Exec(`DELETE FROM snapshots_1m WHERE timestamp < ?`, nowMs-oneDayMs); err != nil {
		return err
	}
	if _, err := d.db.Exec(`DELETE FROM snapshots_5m WHERE timestamp < ?`, nowMs-retentionMs); err != nil {
		return err
	}
	return nil
}

// SaveConnections persists the current connection state to the database.
func (d *DB) SaveConnections(entries []tracker.Entry, keys []tracker.ConnectionKey) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Clear old connections and write fresh state.
	if _, err := tx.Exec(`DELETE FROM connections`); err != nil {
		return err
	}

	stmt, err := tx.Prepare(`INSERT INTO connections (key, data, last_updated) VALUES (?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i, entry := range entries {
		data, err := json.Marshal(entry.Connection)
		if err != nil {
			return err
		}
		if _, err := stmt.Exec(keys[i][:], string(data), entry.LastUpdated); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// LoadConnections reads persisted connections from the database.
func (d *DB) LoadConnections() ([]tracker.Entry, []tracker.ConnectionKey, error) {
	rows, err := d.db.Query(`SELECT key, data, last_updated FROM connections`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var entries []tracker.Entry
	var keys []tracker.ConnectionKey
	for rows.Next() {
		var keyBlob []byte
		var dataJSON string
		var lastUpdated int64
		if err := rows.Scan(&keyBlob, &dataJSON, &lastUpdated); err != nil {
			return nil, nil, err
		}
		var conn tracker.Connection
		if err := json.Unmarshal([]byte(dataJSON), &conn); err != nil {
			return nil, nil, err
		}
		var key tracker.ConnectionKey
		copy(key[:], keyBlob)
		entries = append(entries, tracker.Entry{
			Connection:  conn,
			LastUpdated: lastUpdated,
		})
		keys = append(keys, key)
	}
	return entries, keys, rows.Err()
}

// mergeSummaries picks the last snapshot in the bucket.
//
// Each snapshot is a point-in-time gauge of the system state (cumulative byte
// counters, current connection counts, etc.). The last value in a time bucket
// is the most representative endpoint — it preserves gauge semantics and
// allows the UI to compute deltas between consecutive bucket endpoints to
// derive bandwidth/rates. Averaging these gauges produces values that are
// neither a rate nor a meaningful total, so we avoid it.
func mergeSummaries(summaries []Summary) Summary {
	if len(summaries) == 0 {
		return Summary{}
	}
	// Summaries are ordered by ascending timestamp (from the SQL query),
	// so the last element is the most recent measurement in this bucket.
	return summaries[len(summaries)-1]
}
