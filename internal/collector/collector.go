package collector

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	bpf "github.com/sqldiag/sqldiag/internal/ebpf"
	"github.com/sqldiag/sqldiag/internal/model"
)

type bpfEvent struct {
	Pid        uint32
	Tid        uint32
	StartNs    uint64
	EndNs      uint64
	DurationNs uint64
	Command    uint32
	User       [128]byte
	Db         [128]byte
	ClientIp   [48]byte
	ClientPort uint16
	SqlLen     uint32
	Sql        [4096]byte
}

type Collector struct {
	objs          *bpf.MysqlObjects
	uprobeLink    link.Link
	uretprobeLink link.Link
	ringbuf       *ringbuf.Reader
	mysqlPath     string
	mysqlPid      int
	running       bool
	eventChan     chan *model.Event
}

func NewCollector() *Collector {
	return &Collector{
		eventChan: make(chan *model.Event, 10240),
	}
}

func (c *Collector) AttachByPort(port int) error {
	pid, err := findMySQLProcessByPort(port)
	if err != nil {
		return fmt.Errorf("find mysql process by port %d: %w", port, err)
	}
	return c.AttachByPID(pid)
}

func (c *Collector) AttachByPID(pid int) error {
	mysqlPath, err := findMySQLBinaryByPID(pid)
	if err != nil {
		return fmt.Errorf("find mysql binary path: %w", err)
	}
	return c.Attach(mysqlPath, pid)
}

func (c *Collector) Attach(mysqlBinary string, pid int) error {
	c.mysqlPath = mysqlBinary
	c.mysqlPid = pid

	spec, err := bpf.LoadMysql()
	if err != nil {
		return fmt.Errorf("load eBPF spec: %w", err)
	}

	c.objs = &bpf.MysqlObjects{}
	if err := spec.LoadAndAssign(c.objs, nil); err != nil {
		return fmt.Errorf("load and assign eBPF objects: %w", err)
	}

	offset, err := findSymbolOffset(mysqlBinary, "_Z16dispatch_commandP3THDjPcj")
	if err != nil {
		offset, err = findSymbolOffset(mysqlBinary, "dispatch_command")
		if err != nil {
			return fmt.Errorf("find dispatch_command symbol: %w", err)
		}
	}

	exec, err := link.OpenExecutable(mysqlBinary)
	if err != nil {
		return fmt.Errorf("open executable: %w", err)
	}

	opts := &link.UprobeOptions{
		Address: offset,
		PID:     pid,
	}

	c.uprobeLink, err = exec.Uprobe("", c.objs.DispatchCommandEntry, opts)
	if err != nil {
		return fmt.Errorf("attach uprobe: %w", err)
	}

	c.uretprobeLink, err = exec.Uretprobe("", c.objs.DispatchCommandExit, opts)
	if err != nil {
		return fmt.Errorf("attach uretprobe: %w", err)
	}

	c.ringbuf, err = ringbuf.NewReader(c.objs.Events)
	if err != nil {
		return fmt.Errorf("create ringbuf reader: %w", err)
	}

	c.running = true
	go c.eventLoop()

	return nil
}

func (c *Collector) eventLoop() {
	for c.running {
		record, err := c.ringbuf.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("read ringbuf: %v", err)
			continue
		}

		event, err := parseEvent(record.RawSample)
		if err != nil {
			log.Printf("parse event: %v", err)
			continue
		}

		select {
		case c.eventChan <- event:
		default:
		}
	}
}

func parseEvent(data []byte) (*model.Event, error) {
	if len(data) < int(unsafe.Sizeof(bpfEvent{})) {
		return nil, fmt.Errorf("data too short: %d bytes", len(data))
	}

	var bpfEvt bpfEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &bpfEvt); err != nil {
		return nil, fmt.Errorf("binary read: %w", err)
	}

	event := &model.Event{
		PID:          bpfEvt.Pid,
		TID:          bpfEvt.Tid,
		StartNano:    bpfEvt.StartNs,
		EndNano:      bpfEvt.EndNs,
		DurationNano: bpfEvt.DurationNs,
		Command:      bpfEvt.Command,
		ClientPort:   bpfEvt.ClientPort,
		Timestamp:    time.Now(),
	}

	event.User = nullTerminatedString(bpfEvt.User[:])
	event.DB = nullTerminatedString(bpfEvt.Db[:])
	event.ClientIP = nullTerminatedString(bpfEvt.ClientIp[:])

	sqlLen := int(bpfEvt.SqlLen)
	if sqlLen > model.MaxSQLLen {
		sqlLen = model.MaxSQLLen
	}
	if sqlLen > 0 && sqlLen <= len(bpfEvt.Sql) {
		event.SQL = nullTerminatedString(bpfEvt.Sql[:sqlLen])
	}

	return event, nil
}

func nullTerminatedString(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		return string(b)
	}
	return string(b[:n])
}

func (c *Collector) Events() <-chan *model.Event {
	return c.eventChan
}

func (c *Collector) Close() {
	c.running = false

	if c.uretprobeLink != nil {
		c.uretprobeLink.Close()
	}
	if c.uprobeLink != nil {
		c.uprobeLink.Close()
	}
	if c.ringbuf != nil {
		c.ringbuf.Close()
	}
	if c.objs != nil {
		c.objs.Close()
	}
	close(c.eventChan)
}

func findMySQLProcessByPort(port int) (int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("read /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pidStr := entry.Name()
		var pid int
		if _, err := fmt.Sscanf(pidStr, "%d", &pid); err != nil {
			continue
		}

		cmdlinePath := filepath.Join("/proc", pidStr, "cmdline")
		cmdline, err := os.ReadFile(cmdlinePath)
		if err != nil {
			continue
		}

		cmdParts := strings.Split(string(cmdline), "\x00")
		if len(cmdParts) == 0 {
			continue
		}

		exeName := filepath.Base(cmdParts[0])
		if exeName != "mysqld" && exeName != "mysql" && exeName != "mysqld_safe" {
			continue
		}

		netTcp, err := os.ReadFile(fmt.Sprintf("/proc/%s/net/tcp", pidStr))
		if err != nil {
			continue
		}

		lines := strings.Split(string(netTcp), "\n")
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			localAddr := fields[1]
			addrParts := strings.Split(localAddr, ":")
			if len(addrParts) != 2 {
				continue
			}
			var listenPort int
			if _, err := fmt.Sscanf(addrParts[1], "%x", &listenPort); err == nil && listenPort == port {
				return pid, nil
			}
		}
	}

	return 0, fmt.Errorf("no mysql process listening on port %d", port)
}

func findMySQLBinaryByPID(pid int) (string, error) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	realPath, err := os.Readlink(exePath)
	if err != nil {
		return "", fmt.Errorf("readlink %s: %w", exePath, err)
	}
	return realPath, nil
}

func findSymbolOffset(binaryPath string, symbolName string) (uint64, error) {
	f, err := elf.Open(binaryPath)
	if err != nil {
		return 0, fmt.Errorf("open elf file: %w", err)
	}
	defer f.Close()

	symbols, err := f.Symbols()
	if err != nil {
		dynSymbols, dynErr := f.DynamicSymbols()
		if dynErr != nil {
			return 0, fmt.Errorf("read symbols: %w, dynamic symbols: %w", err, dynErr)
		}
		symbols = dynSymbols
	}

	for _, sym := range symbols {
		if sym.Name == symbolName {
			return sym.Value, nil
		}
	}

	return 0, fmt.Errorf("symbol %q not found in %s", symbolName, binaryPath)
}
