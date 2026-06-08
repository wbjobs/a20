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
	SqlLen     uint32
	ClientPort uint16
	Pad        [2]byte
	User       [128]byte
	Db         [128]byte
	ClientIp   [48]byte
	Sql        [16384]byte
}

type Collector struct {
	objs          *bpf.MysqlObjects
	uprobeLink    link.Link
	uretprobeLink link.Link
	ringbuf       *ringbuf.Reader
	mysqlPath     string
	mysqlPid      int
	symbolOffset  uint64
	thresholdNs   uint64
	running       bool
	eventChan     chan *model.Event
}

func NewCollector() *Collector {
	return &Collector{
		eventChan: make(chan *model.Event, 10240),
	}
}

func (c *Collector) AttachByPort(port int, thresholdMs float64) error {
	pid, err := findMySQLProcessByPort(port)
	if err != nil {
		return fmt.Errorf("find mysql process by port %d: %w", port, err)
	}
	return c.AttachByPID(pid, thresholdMs)
}

func (c *Collector) AttachByPID(pid int, thresholdMs float64) error {
	mysqlPath, err := findMySQLBinaryByPID(pid)
	if err != nil {
		return fmt.Errorf("find mysql binary path: %w", err)
	}
	return c.Attach(mysqlPath, pid, 0, thresholdMs)
}

func (c *Collector) AttachWithOffset(port int, offset uint64, thresholdMs float64) error {
	pid, err := findMySQLProcessByPort(port)
	if err != nil {
		return fmt.Errorf("find mysql process by port %d: %w", port, err)
	}
	mysqlPath, err := findMySQLBinaryByPID(pid)
	if err != nil {
		return fmt.Errorf("find mysql binary path: %w", err)
	}
	return c.Attach(mysqlPath, pid, offset, thresholdMs)
}

func (c *Collector) Attach(mysqlBinary string, pid int, offset uint64, thresholdMs float64) error {
	c.mysqlPath = mysqlBinary
	c.mysqlPid = pid
	c.thresholdNs = uint64(thresholdMs * 1e6)

	spec, err := bpf.LoadMysql()
	if err != nil {
		return fmt.Errorf("load eBPF spec: %w", err)
	}

	c.objs = &bpf.MysqlObjects{}
	if err := spec.LoadAndAssign(c.objs, nil); err != nil {
		return fmt.Errorf("load and assign eBPF objects: %w", err)
	}

	if offset == 0 {
		offset, err = findSymbolOffset(mysqlBinary, "_Z16dispatch_commandP3THDjPcj")
		if err != nil {
			offset, err = findSymbolOffset(mysqlBinary, "dispatch_command")
			if err != nil {
				return fmt.Errorf("find dispatch_command symbol: %w", err)
			}
		}
	}
	c.symbolOffset = offset

	if err := c.setThreshold(c.thresholdNs); err != nil {
		log.Printf("warning: set threshold to eBPF: %v", err)
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

func (c *Collector) setThreshold(thresholdNs uint64) error {
	if c.objs == nil || c.objs.ConfigMap == nil {
		return fmt.Errorf("config map not available")
	}
	key := uint32(0)
	return c.objs.ConfigMap.Put(&key, &thresholdNs)
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
		return nil, fmt.Errorf("data too short: %d bytes (expected %d)", len(data), unsafe.Sizeof(bpfEvent{}))
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
	offset, err := findSymbolOffsetELF(binaryPath, symbolName)
	if err == nil {
		return offset, nil
	}

	if symbolName == "dispatch_command" {
		mangledName := "_Z16dispatch_commandP3THDjPcj"
		offset, err = findSymbolOffsetELF(binaryPath, mangledName)
		if err == nil {
			return offset, nil
		}

		offset, err = findSymbolOffsetByPattern(binaryPath)
		if err == nil {
			return offset, nil
		}
	}

	return 0, fmt.Errorf("symbol %q not found in %s (binary may be stripped), "+
		"try: 1) install mysql-dbgsym package, 2) use --symbol-offset flag, "+
		"3) check if mysqld binary has debug symbols", symbolName, binaryPath)
}

func findSymbolOffsetELF(binaryPath, symbolName string) (uint64, error) {
	f, err := elf.Open(binaryPath)
	if err != nil {
		return 0, fmt.Errorf("open elf file: %w", err)
	}
	defer f.Close()

	symbols, err := f.Symbols()
	if err == nil {
		for _, sym := range symbols {
			if sym.Name == symbolName && sym.Size > 0 {
				return sym.Value, nil
			}
		}
	}

	dynSymbols, err := f.DynamicSymbols()
	if err == nil {
		for _, sym := range dynSymbols {
			if sym.Name == symbolName && sym.Size > 0 {
				return sym.Value, nil
			}
		}
	}

	for _, sec := range f.Sections {
		if sec.Name == ".symtab" || sec.Name == ".dynsym" {
			symtabSection := sec
			var strtabSection *elf.Section
			for _, s := range f.Sections {
				if s.Name == ".strtab" || s.Name == ".dynstr" {
					strtabSection = s
					break
				}
			}
			if strtabSection == nil {
				continue
			}

			strtabData, err := strtabSection.Data()
			if err != nil {
				continue
			}

			symtabData, err := symtabSection.Data()
			if err != nil {
				continue
			}

			symSize := int(symtabSection.Entsize)
			if symSize == 0 {
				continue
			}

			for i := 0; i+symSize <= len(symtabData); i += symSize {
				nameOffset, value, size := readSymbolEntry(symtabData[i:i+symSize], f.Class)
				if nameOffset < uint32(len(strtabData)) {
					name := readCString(strtabData[nameOffset:])
					if name == symbolName && size > 0 {
						return value, nil
					}
				}
			}
		}
	}

	return 0, fmt.Errorf("symbol %q not found", symbolName)
}

func readSymbolEntry(data []byte, class elf.Class) (nameOffset uint32, value uint64, size uint64) {
	if class == elf.ELFCLASS64 {
		nameOffset = binary.LittleEndian.Uint32(data[0:4])
		value = binary.LittleEndian.Uint64(data[8:16])
		size = binary.LittleEndian.Uint64(data[32:40])
	} else {
		nameOffset = binary.LittleEndian.Uint32(data[0:4])
		value = uint64(binary.LittleEndian.Uint32(data[4:8]))
		size = uint64(binary.LittleEndian.Uint32(data[16:20]))
	}
	return
}

func readCString(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}

func findSymbolOffsetByPattern(binaryPath string) (uint64, error) {
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		return 0, fmt.Errorf("read binary: %w", err)
	}

	patterns := [][]byte{
		{0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53},
		{0x55, 0x48, 0x89, 0xe5, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53},
		{0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x89, 0xe5, 0x41, 0x57},
	}

	for _, pattern := range patterns {
		offset := findPattern(data, pattern)
		if offset > 0 {
			return uint64(offset), nil
		}
	}

	return 0, fmt.Errorf("pattern not found")
}

func findPattern(data, pattern []byte) int {
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
