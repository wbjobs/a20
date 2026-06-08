package report

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/olekukonko/tablewriter"

	"github.com/sqldiag/sqldiag/internal/model"
)

type Formatter struct {
	thresholdMs float64
}

func NewFormatter(thresholdMs float64) *Formatter {
	return &Formatter{
		thresholdMs: thresholdMs,
	}
}

func (f *Formatter) PrintSlowQuery(event *model.Event) {
	if event.DurationMs() <= f.thresholdMs {
		return
	}

	fmt.Printf("\n%s [SLOW QUERY] %.2fms\n",
		event.Timestamp.Format("2006-01-02 15:04:05.000"),
		event.DurationMs())
	fmt.Printf("  Command: %s\n", event.CommandName())
	if event.User != "" {
		fmt.Printf("  User:    %s\n", event.User)
	}
	if event.DB != "" {
		fmt.Printf("  DB:      %s\n", event.DB)
	}
	if event.ClientIP != "" {
		fmt.Printf("  Client:  %s:%d\n", event.ClientIP, event.ClientPort)
	}
	if event.SQLFingerprint != "" {
		fmt.Printf("  Fingerprint: %s\n", f.truncateSQL(event.SQLFingerprint, 100))
	}
	fmt.Printf("  SQL:     %s\n", f.truncateSQL(event.SQL, 200))
	if event.ExecutionPlan != "" {
		fmt.Printf("  Plan:    %s\n", event.ExecutionPlan)
	}
}

func (f *Formatter) truncateSQL(sql string, maxLen int) string {
	if len(sql) <= maxLen {
		return sql
	}
	return sql[:maxLen] + "..."
}

func (f *Formatter) PrintReport(report *model.Report) {
	fmt.Println("=" + strings.Repeat("=", 78))
	fmt.Println("  MySQL Slow Query Analysis Report")
	fmt.Println("=" + strings.Repeat("=", 78))
	fmt.Printf("  Generated At:  %s\n", report.GeneratedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Time Range:    %s -> %s\n", report.Since.Format("2006-01-02 15:04:05"), report.GeneratedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Threshold:     %.0fms\n", report.ThresholdMs)
	fmt.Printf("  Total Queries: %d\n", report.TotalQueries)
	fmt.Printf("  Slow Queries:  %d (%.2f%%)\n", report.SlowQueries,
		float64(report.SlowQueries)/float64(report.TotalQueries)*100)
	if len(report.AnomalyAlerts) > 0 {
		fmt.Printf("  Anomaly Alerts: %d\n", len(report.AnomalyAlerts))
	}
	fmt.Println()

	f.PrintAggregateTable("By User", report.ByUser)
	fmt.Println()
	f.PrintAggregateTable("By Database", report.ByDB)
	fmt.Println()
	f.PrintAggregateTable("By Client IP", report.ByClientIP)
	fmt.Println()
	f.PrintFingerprintTable("By SQL Fingerprint", report.ByFingerprint)
	fmt.Println()
	if len(report.AnomalyAlerts) > 0 {
		f.PrintAnomalyTable("Anomaly Alerts", report.AnomalyAlerts)
		fmt.Println()
	}
	f.PrintTopSlowQueries(report.TopSlowQueries)
}

func (f *Formatter) PrintAggregateTable(title string, data map[string]*model.AggregateStats) {
	if len(data) == 0 {
		return
	}

	fmt.Printf("  %s\n", title)
	fmt.Println("  " + strings.Repeat("-", 76))

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Key", "Count", "Total(ms)", "Avg(ms)", "P95(ms)", "Max(ms)", "Min(ms)"})
	table.SetAutoWrapText(false)
	table.SetBorder(true)
	table.SetCenterSeparator("|")
	table.SetColumnSeparator("|")
	table.SetRowSeparator("-")
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_RIGHT)
	table.SetColWidth(20)

	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return data[keys[i]].TotalDuration > data[keys[j]].TotalDuration
	})

	for _, key := range keys {
		stats := data[key]
		table.Append([]string{
			key,
			fmt.Sprintf("%d", stats.Count),
			fmt.Sprintf("%.2f", stats.TotalDuration),
			fmt.Sprintf("%.2f", stats.AvgDuration),
			fmt.Sprintf("%.2f", stats.P95Duration),
			fmt.Sprintf("%.2f", stats.MaxDuration),
			fmt.Sprintf("%.2f", stats.MinDuration),
		})
	}

	table.Render()
}

func (f *Formatter) PrintTopSlowQueries(events []*model.Event) {
	if len(events) == 0 {
		return
	}

	topCount := len(events)
	if topCount > 10 {
		topCount = 10
	}

	fmt.Printf("  Top %d Slow Queries\n", topCount)
	fmt.Println("  " + strings.Repeat("-", 76))

	for i, event := range events {
		if i >= topCount {
			break
		}
		fmt.Printf("\n  #%d [%.2fms] %s\n", i+1, event.DurationMs(), event.Timestamp.Format("2006-01-02 15:04:05.000"))
		fmt.Printf("    User:   %s\n", f.valueOrDefault(event.User, "unknown"))
		fmt.Printf("    DB:     %s\n", f.valueOrDefault(event.DB, "unknown"))
		fmt.Printf("    Client: %s:%d\n", f.valueOrDefault(event.ClientIP, "unknown"), event.ClientPort)
		fmt.Printf("    SQL:    %s\n", f.truncateSQL(event.SQL, 150))
	}
}

func (f *Formatter) valueOrDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func (f *Formatter) PrintFingerprintTable(title string, data map[uint64]*model.FingerprintStats) {
	if len(data) == 0 {
		return
	}

	fmt.Printf("  %s\n", title)
	fmt.Println("  " + strings.Repeat("-", 76))

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"#", "Count", "Total(ms)", "Avg(ms)", "P95(ms)", "Max(ms)", "Min(ms)", "Fingerprint"})
	table.SetAutoWrapText(false)
	table.SetBorder(true)
	table.SetCenterSeparator("|")
	table.SetColumnSeparator("|")
	table.SetRowSeparator("-")
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_RIGHT)
	table.SetColWidth(20)

	keys := make([]uint64, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return data[keys[i]].TotalDuration > data[keys[j]].TotalDuration
	})

	topCount := len(keys)
	if topCount > 10 {
		topCount = 10
	}

	for idx := 0; idx < topCount; idx++ {
		stats := data[keys[idx]]
		fp := f.truncateSQL(stats.Fingerprint, 40)
		table.Append([]string{
			fmt.Sprintf("%d", idx+1),
			fmt.Sprintf("%d", stats.Count),
			fmt.Sprintf("%.2f", stats.TotalDuration),
			fmt.Sprintf("%.2f", stats.AvgDuration),
			fmt.Sprintf("%.2f", stats.P95Duration),
			fmt.Sprintf("%.2f", stats.MaxDuration),
			fmt.Sprintf("%.2f", stats.MinDuration),
			fp,
		})
	}

	table.Render()
}

func (f *Formatter) PrintAnomalyTable(title string, alerts []*model.AnomalyAlert) {
	if len(alerts) == 0 {
		return
	}

	fmt.Printf("  %s\n", title)
	fmt.Println("  " + strings.Repeat("-", 76))

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Time", "Severity", "Z-Score", "Current(ms)", "Mean(ms)", "StdDev(ms)", "Fingerprint"})
	table.SetAutoWrapText(false)
	table.SetBorder(true)
	table.SetCenterSeparator("|")
	table.SetColumnSeparator("|")
	table.SetRowSeparator("-")
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_RIGHT)
	table.SetColWidth(20)

	displayCount := len(alerts)
	if displayCount > 20 {
		displayCount = 20
	}

	for i := len(alerts) - displayCount; i < len(alerts); i++ {
		alert := alerts[i]
		fp := f.truncateSQL(alert.Fingerprint, 40)
		table.Append([]string{
			alert.Timestamp.Format("15:04:05"),
			alert.Severity,
			fmt.Sprintf("%.2f", alert.ZScore),
			fmt.Sprintf("%.2f", alert.CurrentDuration),
			fmt.Sprintf("%.2f", alert.Mean),
			fmt.Sprintf("%.2f", alert.StdDev),
			fp,
		})
	}

	table.Render()
}

func (f *Formatter) PrintLiveStats(total int64, slow int64) {
	fmt.Printf("\r  Queries: %d | Slow: %d (threshold: %.0fms)   ", total, slow, f.thresholdMs)
}
