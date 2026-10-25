// Package migrations holds the versioned SQL schema migrations, embedded in
// the binary and applied on startup.
// Files are named NNNN_description.up.sql and NNNN_description.down.sql.
package migrations

import "embed"

// FS contains every *.sql migration file.
//
//go:embed *.sql
var FS embed.FS
