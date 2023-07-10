package file_readv

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data -target $CURR_ARCH readv readv.bpf.c -- -I../../../../headers
func getEbpfObject() (*readvObjects, error) {
	var bpfObj readvObjects
	err := loadReadvObjects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}

type ReadvEventData struct {
	readvEventData
}

type ReadvDetector struct {
	ebpfLink      link.Link
	ringbufReader *ringbuf.Reader
}

func NewReadvDetector() *ReadvDetector {
	return &ReadvDetector{}
}

func (p *ReadvDetector) Start() error {
	bpfObjs, err := getEbpfObject()
	if err != nil {
		return err
	}

	l, err := link.Kprobe("__x64_sys_readv", bpfObjs.KprobeReadv, nil)
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

func (p *ReadvDetector) Close() error {
	err := p.ebpfLink.Close()
	if err != nil {
		return err
	}

	return p.ringbufReader.Close()
}

func (p *ReadvDetector) Read() (ReadvEventData, error) {
	var event ReadvEventData
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

func (p *ReadvDetector) ReadAsInterface() (any, error) {
	return p.Read()
}
