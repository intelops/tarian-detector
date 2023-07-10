package file_write

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data -target $CURR_ARCH write write.bpf.c -- -I../../../../headers
func getEbpfObject() (*writeObjects, error) {
	var bpfObj writeObjects
	err := loadWriteObjects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}

type WriteEventData struct {
	writeEventData
}

type WriteDetector struct {
	ebpfLink      link.Link
	ringbufReader *ringbuf.Reader
}

func NewWriteDetector() *WriteDetector {
	return &WriteDetector{}
}

func (p *WriteDetector) Start() error {
	bpfObjs, err := getEbpfObject()
	if err != nil {
		return err
	}

	l, err := link.Kprobe("__x64_sys_write", bpfObjs.KprobeWrite, nil)
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

func (p *WriteDetector) Close() error {
	err := p.ebpfLink.Close()
	if err != nil {
		return err
	}

	return p.ringbufReader.Close()
}

func (p *WriteDetector) Read() (WriteEventData, error) {
	var event WriteEventData
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

func (p *WriteDetector) ReadAsInterface() (any, error) {
	return p.Read()
}
