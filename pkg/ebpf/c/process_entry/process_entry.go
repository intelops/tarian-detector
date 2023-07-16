package process_entry

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data entry entry.bpf.c -- -I../../../../headers
func getEbpfObject() (*entryObjects, error) {
	var bpfObj entryObjects
	err := loadEntryObjects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}

// EntryEventData is the exported data from the eBPF struct counterpart
// The intention is to use the proper Go string instead of byte arrays from C.
// It makes it simpler to use and can generate proper json.
type EntryEventData struct {
	Pid            uint32
	Tgid           uint32
	Uid            uint32
	Gid            uint32
	SyscallNr      int32
	Comm           string
	Cwd            string
	BinaryFilepath string
	UserComm       []string
}

func newEntryEventDataFromEbpf(e entryEventData) *EntryEventData {
	evt := &EntryEventData{
		Pid:            e.Pid,
		Tgid:           e.Tgid,
		Uid:            e.Uid,
		Gid:            e.Gid,
		SyscallNr:      e.SyscallNr,
		Comm:           unix.ByteSliceToString(e.Comm[:]),
		Cwd:            unix.ByteSliceToString(e.Cwd[:]),
		BinaryFilepath: unix.ByteSliceToString(e.BinaryFilepath[:]),
		UserComm:       []string{},
	}

	for _, v := range e.UserComm[:] {
		s := unix.ByteSliceToString(v[:])

		if s != "" {
			evt.UserComm = append(evt.UserComm, s)
		}
	}

	return evt
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

	l, err := link.Tracepoint("syscalls", "sys_enter_execve", bpfObjs.ExecveEntry, nil)
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

func (p *ProcessEntryDetector) Read() (*EntryEventData, error) {
	var ebpfEvent entryEventData
	record, err := p.ringbufReader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, err
		}
		return nil, err
	}

	// Parse the ringbuf event entry into a bpfEvent structure.
	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &ebpfEvent); err != nil {
		return nil, err
	}

	exportedEvent := newEntryEventDataFromEbpf(ebpfEvent)

	return exportedEvent, nil
}

func (p *ProcessEntryDetector) ReadAsInterface() (any, error) {
	return p.Read()
}
