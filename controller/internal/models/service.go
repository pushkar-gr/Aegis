package models

import "time"

type Service struct {
	Name        string    `json:"name"`
	Id          int       `json:"id"`
	Description string    `json:"description"`
	IpPort      string    `json:"ip_port"`
	CreatedAt   time.Time `json:"created_at"`
}

type ActiveService struct {
	Service
	TimeLeft  int       `json:"time_left"`
	UpdatedAt time.Time `json:"updated_at"`
}
