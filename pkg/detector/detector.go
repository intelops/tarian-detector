package detector

type EventDetector interface {
	Start() error
	Close() error
	ReadAsInterface() (any, error)
}

type detectorReadReturn struct {
	eventData any
	err       error
}

type EventsDetector struct {
	detectors  []EventDetector
	eventQueue chan detectorReadReturn
	started    bool
	closed     bool
}

func NewEventsDetector() *EventsDetector {
	return &EventsDetector{
		detectors:  make([]EventDetector, 0),
		eventQueue: make(chan detectorReadReturn, 1),
		started:    false,
		closed:     false,
	}
}

func (t *EventsDetector) Add(detector EventDetector) {
	t.detectors = append(t.detectors, detector)
}

func (t *EventsDetector) Start() error {
	for _, detector := range t.detectors {
		err := detector.Start()
		if err != nil {
			return err
		}

		d := detector
		go func() {
			for {
				if t.closed {
					return
				}

				event, err := d.ReadAsInterface()
				t.eventQueue <- detectorReadReturn{event, err}
			}
		}()
	}

	t.started = true

	return nil
}

func (t *EventsDetector) Close() error {
	t.closed = true

	for _, detector := range t.detectors {
		err := detector.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

func (t *EventsDetector) ReadAsInterface() (any, error) {
	r := <-t.eventQueue

	return r.eventData, r.err
}
