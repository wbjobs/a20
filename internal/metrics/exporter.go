package metrics

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/sqldiag/sqldiag/internal/model"
)

const (
	defaultMetricsAddr = ":9090"
	defaultMetricsPath = "/metrics"
)

type Exporter struct {
	mu             sync.Mutex
	registry       *prometheus.Registry
	queryDuration  *prometheus.HistogramVec
	queryTotal     *prometheus.CounterVec
	slowQueryTotal *prometheus.CounterVec
	anomalyTotal   *prometheus.CounterVec
	server         *http.Server
	addr           string
	path           string
	enabled        bool
}

func NewExporter(addr, path string) *Exporter {
	if addr == "" {
		addr = defaultMetricsAddr
	}
	if path == "" {
		path = defaultMetricsPath
	}

	reg := prometheus.NewRegistry()

	queryDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mysql_query_duration_seconds",
			Help:    "MySQL query execution time in seconds",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
		},
		[]string{"user", "db", "client_ip", "command", "sql_fingerprint_hash"},
	)

	queryTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mysql_queries_total",
			Help: "Total number of MySQL queries",
		},
		[]string{"user", "db", "client_ip", "command"},
	)

	slowQueryTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mysql_slow_queries_total",
			Help: "Total number of slow MySQL queries",
		},
		[]string{"user", "db", "client_ip", "command"},
	)

	anomalyTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mysql_query_anomalies_total",
			Help: "Total number of anomalous query executions detected",
		},
		[]string{"user", "db", "severity"},
	)

	reg.MustRegister(queryDuration, queryTotal, slowQueryTotal, anomalyTotal)

	return &Exporter{
		registry:       reg,
		queryDuration:  queryDuration,
		queryTotal:     queryTotal,
		slowQueryTotal: slowQueryTotal,
		anomalyTotal:   anomalyTotal,
		addr:           addr,
		path:           path,
		enabled:        true,
	}
}

func (e *Exporter) Start() error {
	if !e.enabled {
		return nil
	}

	mux := http.NewServeMux()
	mux.Handle(e.path, promhttp.HandlerFor(e.registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	e.server = &http.Server{
		Addr:    e.addr,
		Handler: mux,
	}

	go func() {
		fmt.Printf("Metrics server listening on %s%s\n", e.addr, e.path)
		if err := e.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Metrics server error: %v\n", err)
		}
	}()

	return nil
}

func (e *Exporter) Stop() error {
	if e.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return e.server.Shutdown(ctx)
}

func (e *Exporter) ObserveEvent(event *model.Event, thresholdMs float64) {
	if !e.enabled || event == nil {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	command := event.CommandName()
	duration := float64(event.DurationNano) / 1e9
	fpHex := strconv.FormatUint(event.SQLFingerprintHash, 16)

	e.queryDuration.WithLabelValues(
		event.User,
		event.DB,
		event.ClientIP,
		command,
		fpHex,
	).Observe(duration)

	e.queryTotal.WithLabelValues(
		event.User,
		event.DB,
		event.ClientIP,
		command,
	).Inc()

	if event.DurationMs() > thresholdMs {
		e.slowQueryTotal.WithLabelValues(
			event.User,
			event.DB,
			event.ClientIP,
			command,
		).Inc()
	}
}

func (e *Exporter) ObserveAnomaly(alert *model.AnomalyAlert, user, db string) {
	if !e.enabled || alert == nil {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.anomalyTotal.WithLabelValues(
		user,
		db,
		alert.Severity,
	).Inc()
}
