package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/sqldiag/sqldiag/internal/aggregator"
	"github.com/sqldiag/sqldiag/internal/collector"
	"github.com/sqldiag/sqldiag/internal/model"
)

var (
	sinceStr        string
	outputFile      string
	reportPort      int
	reportPID       int
	reportSymbolOff uint64
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate MySQL slow query analysis report",
	Long: `Generate a detailed JSON report of MySQL slow queries.
The report includes:
- Total and slow query counts
- Aggregation statistics by user, database, and client IP
- Top slow queries
- P95, average, max, and min query durations

Examples:
  sqldiag report --since 1h -p 3306
  sqldiag report --since 30m --pid 12345 -o report.json
  sqldiag report --since 2h -p 3306 --threshold 200`,
	RunE: runReport,
}

func init() {
	reportCmd.Flags().StringVar(&sinceStr, "since", "1h", "Time range for report (e.g., 1h, 30m, 2h)")
	reportCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path (default: stdout)")
	reportCmd.Flags().IntVarP(&reportPort, "port", "p", 3306, "MySQL port to monitor")
	reportCmd.Flags().IntVar(&reportPID, "pid", 0, "MySQL process ID (optional, auto-detected by port)")
	reportCmd.Flags().Uint64Var(&reportSymbolOff, "symbol-offset", 0, "Manual symbol offset for dispatch_command (for stripped binaries)")
	rootCmd.AddCommand(reportCmd)
}

func runReport(cmd *cobra.Command, args []string) error {
	duration, err := parseDuration(sinceStr)
	if err != nil {
		return fmt.Errorf("parse --since: %w", err)
	}

	if duration <= 0 {
		return fmt.Errorf("duration must be positive")
	}

	if thresholdMs <= 0 {
		return fmt.Errorf("threshold must be positive")
	}

	since := time.Now().Add(-duration)
	agg := aggregator.NewAggregator(thresholdMs, since)
	c := collector.NewCollector()

	if reportPID > 0 {
		fmt.Printf("Attaching to MySQL process PID %d...\n", reportPID)
		err = c.AttachByPID(reportPID, thresholdMs)
	} else if reportSymbolOff > 0 {
		fmt.Printf("Attaching to MySQL on port %d with symbol offset 0x%x...\n", reportPort, reportSymbolOff)
		err = c.AttachWithOffset(reportPort, reportSymbolOff, thresholdMs)
	} else {
		fmt.Printf("Attaching to MySQL on port %d...\n", reportPort)
		err = c.AttachByPort(reportPort, thresholdMs)
	}
	if err != nil {
		return fmt.Errorf("attach to MySQL: %w (note: this tool requires Linux kernel >= 5.8 with BPF support and root privileges)", err)
	}
	defer c.Close()

	fmt.Printf("Collecting data for %s...\n", duration)
	fmt.Printf("Threshold: %.0fms\n", thresholdMs)
	fmt.Println("Press Ctrl+C to stop early and generate report")
	fmt.Println()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	timer := time.NewTimer(duration)
	defer timer.Stop()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	remaining := duration

	for {
		select {
		case event := <-c.Events():
			if event == nil {
				continue
			}
			agg.Add(event)

		case <-ticker.C:
			remaining -= time.Second
			total, slow := agg.GetStats()
			fmt.Printf("\r  Time remaining: %-10s  Queries: %-6d  Slow: %-6d   ",
				formatDuration(remaining), total, slow)

		case <-sigChan:
			fmt.Println()
			fmt.Println("\nStopping early, generating report...")
			return generateReport(agg)

		case <-timer.C:
			fmt.Println()
			fmt.Println("\nCollection complete, generating report...")
			return generateReport(agg)
		}
	}
}

func generateReport(agg *aggregator.Aggregator) error {
	reportData := agg.GetReport()

	jsonData, err := json.MarshalIndent(reportData, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}

	if outputFile != "" {
		if err := os.WriteFile(outputFile, jsonData, 0644); err != nil {
			return fmt.Errorf("write report to %s: %w", outputFile, err)
		}
		fmt.Printf("Report saved to: %s\n", outputFile)
		fmt.Printf("Total queries: %d, Slow queries: %d\n", reportData.TotalQueries, reportData.SlowQueries)
	} else {
		fmt.Println(string(jsonData))
	}

	return nil
}

func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}

	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration format %q: use values like '1h', '30m', '2h30m'", s)
	}
	return d, nil
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

func unusedModel() *model.Event {
	return nil
}
