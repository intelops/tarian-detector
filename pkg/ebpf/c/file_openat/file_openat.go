package file_openat

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -target $CURR_ARCH -type event_data openat openat.bpf.c -- -I../../../../headers
func getEbpfObject() (*openatObjects, error) {
	var bpfObj openatObjects
	err := loadOpenatObjects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}

type OpenatEventData struct {
	openatEventData
}

type OpenatDetector struct {
	ebpfLink      link.Link
	ringbufReader *ringbuf.Reader
}

func NewOpenatDetector() *OpenatDetector {
	return &OpenatDetector{}
}

func (o *OpenatDetector) Start() error {
	bpfObjs, err := getEbpfObject()
	if err != nil {
		return err
	}

	l, err := link.Kprobe("__x64_sys_openat", bpfObjs.KprobeOpenat, nil)
	if err != nil {
		return err
	}

	o.ebpfLink = l

	rd, err := ringbuf.NewReader(bpfObjs.Event)
	if err != nil {
		return err
	}

	o.ringbufReader = rd
	return nil
}

func (o *OpenatDetector) Close() error {
	err := o.ebpfLink.Close()
	if err != nil {
		return err
	}

	return o.ringbufReader.Close()
}

func (o *OpenatDetector) Read() (OpenatEventData, error) {
	var event OpenatEventData
	record, err := o.ringbufReader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return event, err
		}

		return event, err
	}

	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
		return event, err
	}

	return event, nil
}

func (o *OpenatDetector) ReadAsInterface() (any, error) {
	return o.Read()
}
