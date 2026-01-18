package models

import "time"

type Service struct {
	Name        string    `json:"name"`
	Id          int       `json:"id"`
	Description string    `json:"description"`
	IpPort      string    `json:"ip_port"`
	CreatedAt   time.Time `json:"created_at"`
}
