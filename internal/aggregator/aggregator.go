package aggregator

import (
	"math"
	"sort"
	"sync"
	"time"

	"github.com/sqldiag/sqldiag/internal/model"
)

const (
	anomalyZScoreThreshold = 3.0
	minSamplesForAnomaly   = 30
)

type rollingStats struct {
	sum   float64
	sumSq float64
	count int64
}

type Aggregator struct {
	mu              sync.RWMutex
	events          []*model.Event
	byUser          map[string]*model.AggregateStats
	byDB            map[string]*model.AggregateStats
	byClientIP      map[string]*model.AggregateStats
	byFingerprint   map[uint64]*model.FingerprintStats
	rollingStats    map[uint64]*rollingStats
	anomalyAlerts   []*model.AnomalyAlert
	thresholdMs     float64
	since           time.Time
	totalQueries    int64
	slowQueries     int64
	anomalyEnabled  bool
}

func NewAggregator(thresholdMs float64, since time.Time) *Aggregator {
	return &Aggregator{
		events:        make([]*model.Event, 0),
		byUser:        make(map[string]*model.AggregateStats),
		byDB:          make(map[string]*model.AggregateStats),
		byClientIP:    make(map[string]*model.AggregateStats),
		byFingerprint: make(map[uint64]*model.FingerprintStats),
		rollingStats:  make(map[uint64]*rollingStats),
		anomalyAlerts: make([]*model.AnomalyAlert, 0),
		thresholdMs:   thresholdMs,
		since:         since,
		anomalyEnabled: true,
	}
}

func (a *Aggregator) EnableAnomalyDetection(enable bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.anomalyEnabled = enable
}

func (a *Aggregator) AnomalyAlerts() []*model.AnomalyAlert {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([]*model.AnomalyAlert, len(a.anomalyAlerts))
	copy(result, a.anomalyAlerts)
	return result
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
	a.updateFingerprintStats(event)

	if a.anomalyEnabled {
		a.checkAnomaly(event)
	}
}

func (a *Aggregator) updateFingerprintStats(event *model.Event) {
	if event.SQLFingerprintHash == 0 {
		return
	}

	stats, exists := a.byFingerprint[event.SQLFingerprintHash]
	if !exists {
		stats = &model.FingerprintStats{
			AggregateStats: model.AggregateStats{
				MinDuration: event.DurationMs(),
			},
			Fingerprint: event.SQLFingerprint,
			ExampleSQL:  event.SQL,
		}
		a.byFingerprint[event.SQLFingerprintHash] = stats
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

func (a *Aggregator) checkAnomaly(event *model.Event) {
	if event.SQLFingerprintHash == 0 {
		return
	}

	rs, exists := a.rollingStats[event.SQLFingerprintHash]
	if !exists {
		rs = &rollingStats{}
		a.rollingStats[event.SQLFingerprintHash] = rs
	}

	duration := event.DurationMs()
	rs.sum += duration
	rs.sumSq += duration * duration
	rs.count++

	if rs.count < minSamplesForAnomaly {
		return
	}

	mean := rs.sum / float64(rs.count)
	variance := (rs.sumSq / float64(rs.count)) - (mean * mean)
	if variance < 0 {
		variance = 0
	}
	stdDev := math.Sqrt(variance)

	if stdDev == 0 {
		return
	}

	zScore := (duration - mean) / stdDev

	if zScore >= anomalyZScoreThreshold {
		severity := "WARNING"
		if zScore >= 5.0 {
			severity = "CRITICAL"
		} else if zScore >= 4.0 {
			severity = "ERROR"
		}

		alert := &model.AnomalyAlert{
			Timestamp:       event.Timestamp,
			FingerprintHash: event.SQLFingerprintHash,
			Fingerprint:     event.SQLFingerprint,
			CurrentDuration: duration,
			Mean:            mean,
			StdDev:          stdDev,
			ZScore:          zScore,
			Severity:        severity,
		}
		a.anomalyAlerts = append(a.anomalyAlerts, alert)
	}
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
	fpDurations := make(map[uint64][]float64)

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

		if event.SQLFingerprintHash != 0 {
			fpDurations[event.SQLFingerprintHash] = append(fpDurations[event.SQLFingerprintHash], event.DurationMs())
		}
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

	for key, durations := range fpDurations {
		if stats, ok := a.byFingerprint[key]; ok {
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

	alerts := make([]*model.AnomalyAlert, len(a.anomalyAlerts))
	copy(alerts, a.anomalyAlerts)

	return &model.Report{
		GeneratedAt:    time.Now(),
		Since:          a.since,
		TotalQueries:   a.totalQueries,
		SlowQueries:    a.slowQueries,
		ThresholdMs:    a.thresholdMs,
		ByUser:         a.copyStatsMap(a.byUser),
		ByDB:           a.copyStatsMap(a.byDB),
		ByClientIP:     a.copyStatsMap(a.byClientIP),
		ByFingerprint:  a.copyFingerprintStatsMap(a.byFingerprint),
		TopSlowQueries: topSlow,
		AnomalyAlerts:  alerts,
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

func (a *Aggregator) copyFingerprintStatsMap(src map[uint64]*model.FingerprintStats) map[uint64]*model.FingerprintStats {
	dst := make(map[uint64]*model.FingerprintStats, len(src))
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
