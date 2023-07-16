package process_exit

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data exit exit.bpf.c -- -I../../../../headers
func getEbpfObject() (*exitObjects, error) {
	var bpfObj exitObjects
	err := loadExitObjects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}

type ExitEventData struct {
	Pid       uint32
	Tgid      uint32
	Uid       uint32
	Gid       uint32
	SyscallNr int32
	Ret       int64
	Comm      string
	Cwd       string
}

func newExitEventDataFromEbpf(e exitEventData) *ExitEventData {
	evt := &ExitEventData{
		Pid:       e.Pid,
		Tgid:      e.Tgid,
		Uid:       e.Uid,
		Gid:       e.Gid,
		SyscallNr: e.SyscallNr,
		Ret:       e.Ret,
		Comm:      unix.ByteSliceToString(e.Comm[:]),
		Cwd:       unix.ByteSliceToString(e.Cwd[:]),
	}

	return evt
}

type ProcessExitDetector struct {
	ebpfLink      link.Link
	ringbufReader *ringbuf.Reader
}

func NewProcessExitDetector() *ProcessExitDetector {
	return &ProcessExitDetector{}
}

func (p *ProcessExitDetector) Start() error {
	bpfObjs, err := getEbpfObject()
	if err != nil {
		return err
	}

	l, err := link.Tracepoint("syscalls", "sys_exit_execve", bpfObjs.ExecveExit, nil)
	if err != nil {
		return err
	}

	p.ebpfLink = l

	// Open a ringbuf reader from userspace RINGBUF map described in the
	// eBPF C program.
	rd, err := ringbuf.NewReader(bpfObjs.Event)
	if err != nil {
		return err
	}

	p.ringbufReader = rd
	return nil
}

func (p *ProcessExitDetector) Close() error {
	err := p.ebpfLink.Close()
	if err != nil {
		return err
	}

	return p.ringbufReader.Close()
}

func (p *ProcessExitDetector) Read() (*ExitEventData, error) {
	var ebpfEvent exitEventData
	record, err := p.ringbufReader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, err
		}
		return nil, err
	}

	// Parse the ringbuf event exit into a bpfEvent structure.
	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &ebpfEvent); err != nil {
		return nil, err
	}

	exportedEvent := newExitEventDataFromEbpf(ebpfEvent)

	return exportedEvent, nil
}

func (p *ProcessExitDetector) ReadAsInterface() (any, error) {
	return p.Read()
}
