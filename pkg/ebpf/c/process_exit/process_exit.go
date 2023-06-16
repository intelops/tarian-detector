package process_exit

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
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
	exitEventData
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

func (p *ProcessExitDetector) Read() (ExitEventData, error) {
	var event ExitEventData
	record, err := p.ringbufReader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return event, err
		}
		return event, err
	}

	// Parse the ringbuf event exit into a bpfEvent structure.
	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
		return event, err
	}

	return event, nil
}

func (p *ProcessExitDetector) ReadAsInterface() (any, error) {
	return p.Read()
}
