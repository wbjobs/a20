package model

import (
	"encoding/json"
	"fmt"
	"time"
)

const (
	MaxSQLLen   = 16384
	MaxUserLen  = 128
	MaxDBLen    = 128
	MaxIPLen    = 48
)

type Event struct {
	PID          uint32    `json:"pid"`
	TID          uint32    `json:"tid"`
	StartNano    uint64    `json:"start_nano"`
	EndNano      uint64    `json:"end_nano"`
	DurationNano uint64    `json:"duration_nano"`
	Command      uint32    `json:"command"`
	User         string    `json:"user"`
	DB           string    `json:"db"`
	ClientIP     string    `json:"client_ip"`
	ClientPort   uint16    `json:"client_port"`
	SQL          string    `json:"sql"`
	Timestamp    time.Time `json:"timestamp"`
}

func (e *Event) DurationMs() float64 {
	return float64(e.DurationNano) / 1e6
}

func (e *Event) CommandName() string {
	switch e.Command {
	case 3:
		return "COM_QUERY"
	case 22:
		return "COM_STMT_PREPARE"
	case 23:
		return "COM_STMT_EXECUTE"
	default:
		return fmt.Sprintf("COM_%d", e.Command)
	}
}

type AggregateKey struct {
	User     string `json:"user"`
	DB       string `json:"db"`
	ClientIP string `json:"client_ip"`
}

type AggregateStats struct {
	Count         int64   `json:"count"`
	TotalDuration float64 `json:"total_duration_ms"`
	AvgDuration   float64 `json:"avg_duration_ms"`
	MaxDuration   float64 `json:"max_duration_ms"`
	MinDuration   float64 `json:"min_duration_ms"`
	P95Duration   float64 `json:"p95_duration_ms"`
}

type Report struct {
	GeneratedAt    time.Time                  `json:"generated_at"`
	Since          time.Time                  `json:"since"`
	TotalQueries   int64                      `json:"total_queries"`
	SlowQueries    int64                      `json:"slow_queries"`
	ThresholdMs    float64                    `json:"threshold_ms"`
	ByUser         map[string]*AggregateStats `json:"by_user"`
	ByDB           map[string]*AggregateStats `json:"by_db"`
	ByClientIP     map[string]*AggregateStats `json:"by_client_ip"`
	TopSlowQueries []*Event                   `json:"top_slow_queries"`
}

func (r *Report) ToJSON() (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
