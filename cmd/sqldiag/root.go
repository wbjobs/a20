package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "sqldiag",
	Short: "eBPF-based MySQL slow query diagnostic tool",
	Long: `sqldiag is a transparent MySQL slow query diagnostic tool based on eBPF.
It hooks the MySQL dispatch_command function using uprobes to capture all SQL statements
without modifying MySQL code or enabling slow query logs.

Features:
- Real-time SQL performance monitoring with zero overhead
- Capture all SQL statements without enabling slow query log
- Calculate query execution time automatically
- Generate aggregation statistics by user, database, and client IP
- Export JSON reports for further analysis`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var (
	thresholdMs float64
	outputJSON  bool
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().Float64Var(&thresholdMs, "threshold", 100.0, "Slow query threshold in milliseconds")
	rootCmd.PersistentFlags().BoolVar(&outputJSON, "json", false, "Output in JSON format")
}
