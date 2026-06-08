package aggregator

import (
	"sort"
	"sync"
	"time"

	"github.com/sqldiag/sqldiag/internal/model"
)

type Aggregator struct {
	mu           sync.RWMutex
	events       []*model.Event
	byUser       map[string]*model.AggregateStats
	byDB         map[string]*model.AggregateStats
	byClientIP   map[string]*model.AggregateStats
	thresholdMs  float64
	since        time.Time
	totalQueries int64
	slowQueries  int64
}

func NewAggregator(thresholdMs float64, since time.Time) *Aggregator {
	return &Aggregator{
		events:      make([]*model.Event, 0),
		byUser:      make(map[string]*model.AggregateStats),
		byDB:        make(map[string]*model.AggregateStats),
		byClientIP:  make(map[string]*model.AggregateStats),
		thresholdMs: thresholdMs,
		since:       since,
	}
}

func (a *Aggregator) Add(event *model.Event) {
	if event.Timestamp.Before(a.since) {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	a.events = append(a.events, event)
	a.totalQueries++

	if event.DurationMs() > a.thresholdMs {
		a.slowQueries++
	}

	a.updateStats(a.byUser, event.User, event)
	a.updateStats(a.byDB, event.DB, event)
	a.updateStats(a.byClientIP, event.ClientIP, event)
}

func (a *Aggregator) updateStats(statsMap map[string]*model.AggregateStats, key string, event *model.Event) {
	if key == "" {
		key = "unknown"
	}

	stats, exists := statsMap[key]
	if !exists {
		stats = &model.AggregateStats{
			MinDuration: event.DurationMs(),
		}
		statsMap[key] = stats
	}

	stats.Count++
	duration := event.DurationMs()
	stats.TotalDuration += duration
	stats.AvgDuration = stats.TotalDuration / float64(stats.Count)

	if duration > stats.MaxDuration {
		stats.MaxDuration = duration
	}
	if duration < stats.MinDuration {
		stats.MinDuration = duration
	}
}

func (a *Aggregator) calculateP95(durations []float64) float64 {
	if len(durations) == 0 {
		return 0
	}
	sort.Float64s(durations)
	index := int(float64(len(durations)) * 0.95)
	if index >= len(durations) {
		index = len(durations) - 1
	}
	return durations[index]
}

func (a *Aggregator) finalizeP95() {
	userDurations := make(map[string][]float64)
	dbDurations := make(map[string][]float64)
	ipDurations := make(map[string][]float64)

	for _, event := range a.events {
		user := event.User
		if user == "" {
			user = "unknown"
		}
		userDurations[user] = append(userDurations[user], event.DurationMs())

		db := event.DB
		if db == "" {
			db = "unknown"
		}
		dbDurations[db] = append(dbDurations[db], event.DurationMs())

		ip := event.ClientIP
		if ip == "" {
			ip = "unknown"
		}
		ipDurations[ip] = append(ipDurations[ip], event.DurationMs())
	}

	for key, durations := range userDurations {
		if stats, ok := a.byUser[key]; ok {
			stats.P95Duration = a.calculateP95(durations)
		}
	}

	for key, durations := range dbDurations {
		if stats, ok := a.byDB[key]; ok {
			stats.P95Duration = a.calculateP95(durations)
		}
	}

	for key, durations := range ipDurations {
		if stats, ok := a.byClientIP[key]; ok {
			stats.P95Duration = a.calculateP95(durations)
		}
	}
}

func (a *Aggregator) GetReport() *model.Report {
	a.mu.RLock()
	defer a.mu.RUnlock()

	a.finalizeP95()

	topSlow := make([]*model.Event, 0)
	for _, event := range a.events {
		if event.DurationMs() > a.thresholdMs {
			topSlow = append(topSlow, event)
		}
	}

	sort.Slice(topSlow, func(i, j int) bool {
		return topSlow[i].DurationNano > topSlow[j].DurationNano
	})

	if len(topSlow) > 100 {
		topSlow = topSlow[:100]
	}

	return &model.Report{
		GeneratedAt:    time.Now(),
		Since:          a.since,
		TotalQueries:   a.totalQueries,
		SlowQueries:    a.slowQueries,
		ThresholdMs:    a.thresholdMs,
		ByUser:         a.copyStatsMap(a.byUser),
		ByDB:           a.copyStatsMap(a.byDB),
		ByClientIP:     a.copyStatsMap(a.byClientIP),
		TopSlowQueries: topSlow,
	}
}

func (a *Aggregator) copyStatsMap(src map[string]*model.AggregateStats) map[string]*model.AggregateStats {
	dst := make(map[string]*model.AggregateStats, len(src))
	for k, v := range src {
		stats := *v
		dst[k] = &stats
	}
	return dst
}

func (a *Aggregator) GetStats() (total int64, slow int64) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.totalQueries, a.slowQueries
}
