package models

import "time"

type Service struct {
	Name        string    `json:"name"`
	Id          int       `json:"id"`
	Description string    `json:"description"`
	Hostname    string    `json:"hostname"`
	Ip          uint32    `json:"ip"` // network byte order
	Port        uint16    `json:"port"`
	CreatedAt   time.Time `json:"created_at"`
}

type ActiveService struct {
	Service
	TimeLeft  int       `json:"time_left"`
	UpdatedAt time.Time `json:"updated_at"`
}
