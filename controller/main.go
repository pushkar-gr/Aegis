package main

import (
	"fmt"
	"time"
)

func main() {
	fmt.Println("🛡️ Aegis Controller: Online & Waiting...")
	for {
		time.Sleep(1 * time.Hour)
	}
}
