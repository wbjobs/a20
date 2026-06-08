package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/sqldiag/sqldiag/internal/aggregator"
	"github.com/sqldiag/sqldiag/internal/collector"
	"github.com/sqldiag/sqldiag/internal/metrics"
	"github.com/sqldiag/sqldiag/internal/model"
	"github.com/sqldiag/sqldiag/internal/report"
)

var (
	mysqlPort    int
	mysqlPID     int
	duration     time.Duration
	symbolOffset uint64
	enableMetrics bool
	metricsAddr   string
	noPlan        bool
	noAnomaly     bool
)

var mysqlCmd = &cobra.Command{
	Use:   "mysql",
	Short: "Monitor MySQL slow queries in real-time",
	Long: `Monitor MySQL slow queries in real-time using eBPF uprobes.
This command hooks into the MySQL dispatch_command function to capture all SQL statements
and their execution times without modifying MySQL configuration.

Examples:
  sqldiag mysql -p 3306 --threshold 200
  sqldiag mysql --pid 12345 --duration 5m
  sqldiag mysql -p 3306 --json`,
	RunE: runMySQL,
}

func init() {
	mysqlCmd.Flags().IntVarP(&mysqlPort, "port", "p", 3306, "MySQL port to monitor")
	mysqlCmd.Flags().IntVar(&mysqlPID, "pid", 0, "MySQL process ID (optional, auto-detected by port)")
	mysqlCmd.Flags().DurationVar(&duration, "duration", 0, "Monitoring duration (e.g., 1h, 30m). 0 means run until interrupted")
	mysqlCmd.Flags().Uint64Var(&symbolOffset, "symbol-offset", 0, "Manual symbol offset for dispatch_command (for stripped binaries)")
	mysqlCmd.Flags().BoolVar(&enableMetrics, "metrics", false, "Enable Prometheus metrics exporter")
	mysqlCmd.Flags().StringVar(&metricsAddr, "metrics-addr", ":9090", "Prometheus metrics server address")
	mysqlCmd.Flags().BoolVar(&noPlan, "no-plan", false, "Disable execution plan capture")
	mysqlCmd.Flags().BoolVar(&noAnomaly, "no-anomaly", false, "Disable anomaly detection")
	rootCmd.AddCommand(mysqlCmd)
}

func runMySQL(cmd *cobra.Command, args []string) error {
	if thresholdMs <= 0 {
		return fmt.Errorf("threshold must be positive")
	}

	agg := aggregator.NewAggregator(thresholdMs, time.Now())
	agg.EnableAnomalyDetection(!noAnomaly)

	formatter := report.NewFormatter(thresholdMs)
	c := collector.NewCollector()
	c.SetCapturePlan(!noPlan)

	var exporter *metrics.Exporter
	if enableMetrics {
		exporter = metrics.NewExporter(metricsAddr, "/metrics")
		if err := exporter.Start(); err != nil {
			return fmt.Errorf("start metrics server: %w", err)
		}
		defer exporter.Stop()
	}

	var err error
	if mysqlPID > 0 {
		fmt.Printf("Attaching to MySQL process PID %d...\n", mysqlPID)
		err = c.AttachByPID(mysqlPID, thresholdMs)
	} else if symbolOffset > 0 {
		fmt.Printf("Attaching to MySQL on port %d with symbol offset 0x%x...\n", mysqlPort, symbolOffset)
		err = c.AttachWithOffset(mysqlPort, symbolOffset, thresholdMs)
	} else {
		fmt.Printf("Attaching to MySQL on port %d...\n", mysqlPort)
		err = c.AttachByPort(mysqlPort, thresholdMs)
	}
	if err != nil {
		return fmt.Errorf("attach to MySQL: %w (note: this tool requires Linux kernel >= 5.8 with BPF support and root privileges)", err)
	}
	defer c.Close()

	fmt.Println("Monitoring MySQL slow queries...")
	fmt.Printf("Threshold: %.0fms\n", thresholdMs)
	if !noPlan {
		fmt.Println("Execution plan capture: enabled")
	}
	if !noAnomaly {
		fmt.Println("Anomaly detection: enabled (3σ threshold)")
	}
	if enableMetrics {
		fmt.Printf("Metrics: enabled on %s/metrics\n", metricsAddr)
	}
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	var timerChan <-chan time.Time
	if duration > 0 {
		timer := time.NewTimer(duration)
		defer timer.Stop()
		timerChan = timer.C
		fmt.Printf("Monitoring for %s...\n", duration)
		fmt.Println()
	}

	statsTicker := time.NewTicker(1 * time.Second)
	defer statsTicker.Stop()

	alertTicker := time.NewTicker(5 * time.Second)
	defer alertTicker.Stop()

	var lastAlertCount int

	for {
		select {
		case event := <-c.Events():
			if event == nil {
				continue
			}
			agg.Add(event)
			if exporter != nil {
				exporter.ObserveEvent(event, thresholdMs)
			}
			if !outputJSON {
				formatter.PrintSlowQuery(event)
			}

		case <-statsTicker.C:
			if !outputJSON {
				total, slow := agg.GetStats()
				formatter.PrintLiveStats(total, slow)
			}

		case <-alertTicker.C:
			if !noAnomaly && !outputJSON {
				alerts := agg.AnomalyAlerts()
				if len(alerts) > lastAlertCount {
					for i := lastAlertCount; i < len(alerts); i++ {
						alert := alerts[i]
						printAnomalyAlert(alert)
						if exporter != nil {
							exporter.ObserveAnomaly(alert, "", "")
						}
					}
					lastAlertCount = len(alerts)
				}
			}

		case <-sigChan:
			fmt.Println()
			fmt.Println("\nStopping monitoring...")
			return printFinalReport(agg, formatter)

		case <-timerChan:
			fmt.Println()
			fmt.Println("\nMonitoring duration reached, stopping...")
			return printFinalReport(agg, formatter)
		}
	}
}

func printAnomalyAlert(alert *model.AnomalyAlert) {
	fmt.Printf("\n%s ANOMALY ALERT [%s] %s\n",
		alert.Timestamp.Format("15:04:05"),
		alert.Severity,
		alert.Fingerprint)
	fmt.Printf("  Current: %.2fms, Mean: %.2fms, StdDev: %.2fms, Z-Score: %.2f\n\n",
		alert.CurrentDuration, alert.Mean, alert.StdDev, alert.ZScore)
}

func printFinalReport(agg *aggregator.Aggregator, formatter *report.Formatter) error {
	reportData := agg.GetReport()

	if outputJSON {
		jsonStr, err := reportData.ToJSON()
		if err != nil {
			return fmt.Errorf("generate JSON report: %w", err)
		}
		fmt.Println(jsonStr)
	} else {
		fmt.Println()
		formatter.PrintReport(reportData)
	}

	return nil
}

func parseEventForReport(event *model.Event) {
}
