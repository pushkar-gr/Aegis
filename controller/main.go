package main

import (
	"Aegis/controller/database"
	"Aegis/controller/server"
	"log"
	"os"
	"os/signal"
)

// main initializes the database, starts the HTTP server in a separate goroutine,
// and handles graceful shutdown upon receiving an interrupt signal.
func main() {
	// Initialize the SQLite database connection and schema.
	database.InitDB()
	defer database.DB.Close()

	// Start the server in a goroutine so the main thread can listen for signals.
	go server.StartServer()

	// Create a channel to listen for OS interrupt signals (Ctrl+C).
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	// Block until a signal is received.
	<-quit

	log.Println("Interrupt signal received. Shutting down server...")
}
