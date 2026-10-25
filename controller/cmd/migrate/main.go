// Command migrate applies the embedded schema migrations to an Aegis database.
// The controller does the same automatically on startup.
//
//	go run ./cmd/migrate [-dir ./data] up # upgrade to the latest version
//	go run ./cmd/migrate [-dir ./data] status # show current version and pending migrations
//	go run ./cmd/migrate [-dir ./data] down [N] # revert the last N migrations (default 1)
package main

import (
	"Aegis/controller/internal/repository"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

func main() {
	dir := flag.String("dir", "./data", "directory containing "+repository.DBFileName)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: migrate [-dir DIR] up | status | down [N]\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if err := run(*dir, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(dir string, args []string) error {
	if len(args) == 0 {
		flag.Usage()
		return fmt.Errorf("missing command")
	}
	dbPath := filepath.Join(dir, repository.DBFileName)
	ctx := context.Background()

	switch args[0] {
	case "up":
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := repository.Migrate(ctx, dbPath); err != nil {
			return err
		}
		return printStatus(ctx, dbPath)

	case "status":
		return printStatus(ctx, dbPath)

	case "down":
		steps := 1
		if len(args) > 1 {
			n, err := strconv.Atoi(args[1])
			if err != nil || n < 1 {
				return fmt.Errorf("down: N must be a positive number, got %q", args[1])
			}
			steps = n
		}
		if err := repository.MigrateDown(ctx, dbPath, steps); err != nil {
			return err
		}
		return printStatus(ctx, dbPath)
	}
	flag.Usage()
	return fmt.Errorf("unknown command %q", args[0])
}

func printStatus(ctx context.Context, dbPath string) error {
	st, err := repository.MigrationStatus(ctx, dbPath)
	if err != nil {
		return err
	}
	fmt.Printf("database:        %s\n", dbPath)
	fmt.Printf("current version: %d", st.Current)
	if st.Unversioned {
		fmt.Printf(" (detected from an unversioned database)")
	}
	fmt.Printf("\nlatest version:  %d\n", st.Latest)
	if len(st.Pending) == 0 {
		fmt.Println("pending:         none, up to date")
		return nil
	}
	fmt.Println("pending:")
	for _, p := range st.Pending {
		fmt.Println("  -", p)
	}
	return nil
}
