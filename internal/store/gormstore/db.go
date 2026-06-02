package gormstore

import (
	"errors"
	"fmt"
	"strings"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Open creates a *gorm.DB for the given driver + DSN. "postgres" is the
// production runtime driver; "sqlite" remains supported for the test suite
// only (the application wiring in cmd/authserver never selects it). An
// empty driver defaults to "sqlite" to keep test callers terse.
//
// The returned *gorm.DB is safe to share across goroutines; GORM uses
// the underlying *sql.DB pool. The caller is responsible for
// Migrate()-ing the schema before first use.
func Open(driver, dsn string) (*gorm.DB, error) {
	if dsn == "" {
		return nil, errors.New("gormstore: empty DSN")
	}
	drv := strings.ToLower(strings.TrimSpace(driver))
	if drv == "" {
		drv = "sqlite"
	}

	gormCfg := &gorm.Config{
		// Silent logger so that test output and request logs don't get
		// drowned by SQL statements. The application can attach a
		// louder logger via the *gorm.DB.Logger field if needed.
		Logger: logger.Default.LogMode(logger.Silent),
	}

	switch drv {
	case "sqlite":
		// SQLite without foreign keys: enforce at the application
		// layer. _busy_timeout avoids "database is locked" under
		// concurrent test traffic; _journal_mode=WAL gives multi-
		// reader/single-writer concurrency.
		dsn = addSQLitePragmas(dsn)
		return gorm.Open(sqlite.Open(dsn), gormCfg)
	case "postgres":
		return gorm.Open(postgres.Open(dsn), gormCfg)
	default:
		return nil, fmt.Errorf("gormstore: unsupported driver %q (want sqlite|postgres)", driver)
	}
}

// addSQLitePragmas injects the pragmas we want on every SQLite
// connection. Existing values for `_pragma` are kept (multi-occurrence
// is allowed by the driver). The function is a no-op for non-sqlite
// DSNs.
func addSQLitePragmas(dsn string) string {
	pragmas := []string{
		"_pragma=busy_timeout(5000)",
		"_pragma=journal_mode(WAL)",
		"_pragma=synchronous(NORMAL)",
		"_pragma=foreign_keys(ON)",
	}
	for _, p := range pragmas {
		if strings.Contains(dsn, p) {
			continue
		}
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		dsn += sep + p
	}
	return dsn
}
