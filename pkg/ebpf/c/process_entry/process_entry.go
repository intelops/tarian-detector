package process_entry

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data -target $CURR_ARCH entry entry.bpf.c -- -I../../../../headers
func getEbpfObject() (*entryObjects, error) {
	var bpfObj entryObjects
	err := loadEntryObjects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}

type EntryEventData struct {
	entryEventData
}

type ProcessEntryDetector struct {
	ebpfLink      link.Link
	ringbufReader *ringbuf.Reader
}

func NewProcessEntryDetector() *ProcessEntryDetector {
	return &ProcessEntryDetector{}
}

func (p *ProcessEntryDetector) Start() error {
	bpfObjs, err := getEbpfObject()
	if err != nil {
		return err
	}

	l, err := link.Kprobe("__x64_sys_execve", bpfObjs.KprobeExecve, nil)
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

func (p *ProcessEntryDetector) Close() error {
	err := p.ebpfLink.Close()
	if err != nil {
		return err
	}

	return p.ringbufReader.Close()
}

func (p *ProcessEntryDetector) Read() (EntryEventData, error) {
	var event EntryEventData
	record, err := p.ringbufReader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return event, err
		}
		return event, err
	}

	// Parse the ringbuf event entry into a bpfEvent structure.
	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
		return event, err
	}

	return event, nil
}

func (p *ProcessEntryDetector) ReadAsInterface() (any, error) {
	return p.Read()
}
