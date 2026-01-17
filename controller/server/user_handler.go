package server

import (
	"fmt"
	"html"
	"log"
	"net/http"
)

// Welcome is a protected endpoint that displays a personalized message.
func Welcome(w http.ResponseWriter, r *http.Request) {
	val := r.Context().Value(UserKey)
	username, ok := val.(string)

	if !ok {
		log.Println("Error: User context missing in Welcome handler")
		http.Error(w, "Internal server error: user context missing", http.StatusInternalServerError)
		return
	}

	if _, err := fmt.Fprintf(w, "Welcome, %s! This is a protected route.", html.EscapeString(username)); err != nil {
		log.Printf("Error writing response: %v", err)
	}
}
