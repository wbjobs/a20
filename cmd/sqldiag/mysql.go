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
	"github.com/sqldiag/sqldiag/internal/model"
	"github.com/sqldiag/sqldiag/internal/report"
)

var (
	mysqlPort int
	mysqlPID  int
	duration  time.Duration
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
	rootCmd.AddCommand(mysqlCmd)
}

func runMySQL(cmd *cobra.Command, args []string) error {
	if thresholdMs <= 0 {
		return fmt.Errorf("threshold must be positive")
	}

	agg := aggregator.NewAggregator(thresholdMs, time.Now())
	formatter := report.NewFormatter(thresholdMs)
	c := collector.NewCollector()

	var err error
	if mysqlPID > 0 {
		fmt.Printf("Attaching to MySQL process PID %d...\n", mysqlPID)
		err = c.AttachByPID(mysqlPID)
	} else {
		fmt.Printf("Attaching to MySQL on port %d...\n", mysqlPort)
		err = c.AttachByPort(mysqlPort)
	}
	if err != nil {
		return fmt.Errorf("attach to MySQL: %w (note: this tool requires Linux kernel >= 5.8 with BPF support and root privileges)", err)
	}
	defer c.Close()

	fmt.Println("Monitoring MySQL slow queries...")
	fmt.Printf("Threshold: %.0fms\n", thresholdMs)
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

	for {
		select {
		case event := <-c.Events():
			if event == nil {
				continue
			}
			agg.Add(event)
			if !outputJSON {
				formatter.PrintSlowQuery(event)
			}

		case <-statsTicker.C:
			if !outputJSON {
				total, slow := agg.GetStats()
				formatter.PrintLiveStats(total, slow)
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
