package ebpf

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/cilium/ebpf"
)

type MysqlObjects struct {
	DispatchCommandEntry *ebpf.Program `ebpf:"dispatch_command_entry"`
	DispatchCommandExit  *ebpf.Program `ebpf:"dispatch_command_exit"`
	StartMap             *ebpf.Map     `ebpf:"start_map"`
	Events               *ebpf.Map     `ebpf:"events"`
}

func (m *MysqlObjects) Close() error {
	if m.DispatchCommandEntry != nil {
		m.DispatchCommandEntry.Close()
	}
	if m.DispatchCommandExit != nil {
		m.DispatchCommandExit.Close()
	}
	if m.StartMap != nil {
		m.StartMap.Close()
	}
	if m.Events != nil {
		m.Events.Close()
	}
	return nil
}

type MysqlPrograms struct {
	DispatchCommandEntry *ebpf.Program `ebpf:"dispatch_command_entry"`
	DispatchCommandExit  *ebpf.Program `ebpf:"dispatch_command_exit"`
}

func (p *MysqlPrograms) Close() error {
	if p.DispatchCommandEntry != nil {
		p.DispatchCommandEntry.Close()
	}
	if p.DispatchCommandExit != nil {
		p.DispatchCommandExit.Close()
	}
	return nil
}

type MysqlMaps struct {
	StartMap *ebpf.Map `ebpf:"start_map"`
	Events   *ebpf.Map `ebpf:"events"`
}

func (m *MysqlMaps) Close() error {
	if m.StartMap != nil {
		m.StartMap.Close()
	}
	if m.Events != nil {
		m.Events.Close()
	}
	return nil
}

func LoadMysql() (*ebpf.CollectionSpec, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("eBPF is only supported on Linux, current OS: %s", runtime.GOOS)
	}

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return nil, fmt.Errorf("failed to get current file path")
	}

	dir := filepath.Dir(filename)
	objPath := filepath.Join(dir, "mysql_bpfel.o")

	if _, err := os.Stat(objPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("eBPF object file not found at %s: %w\n"+
			"Please run 'make generate' in the project root directory on a Linux system with:\n"+
			"  - clang/llvm >= 14.0\n"+
			"  - kernel headers installed\n"+
			"  - libbpf-dev installed", objPath, err)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("load eBPF collection spec from %s: %w", objPath, err)
	}

	return spec, nil
}
