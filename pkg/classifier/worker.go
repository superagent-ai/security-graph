package classifier

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
)

const maxFrame = 65536

// Worker owns one lazily started, resident classifier. The operator's command
// must implement the ready/request/result JSON-lines protocol. Close it when
// the service exits. Failed or cancelled exchanges discard the whole process.
type Worker struct {
	command Command
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	process *workerProcess
	serial  uint64
}

type workerProcess struct {
	cmd    *exec.Cmd
	in     *os.File
	out    *os.File
	reader *bufio.Reader
	done   chan struct{}
	dir    string
}

func NewWorker(ctx context.Context, command Command) *Worker {
	ctx, cancel := context.WithCancel(ctx)
	command.Args = append([]string(nil), command.Args...)
	return &Worker{command: command, ctx: ctx, cancel: cancel}
}

func (w *Worker) Close() error {
	w.cancel()
	w.mu.Lock()
	defer w.mu.Unlock()
	w.discard()
	return nil
}

func (w *Worker) discard() {
	if p := w.process; p != nil {
		_ = p.cmd.Process.Kill()
		_ = p.in.Close()
		_ = p.out.Close()
		<-p.done // Reap the child before replacing it or removing its scratch home.
		_ = os.RemoveAll(p.dir)
		w.process = nil
	}
}

func (w *Worker) start() error {
	work, err := os.MkdirTemp("", "security-graph-worker-")
	if err != nil {
		return ErrUnavailable
	}
	in, childIn, err := workerInput()
	if err != nil {
		_ = os.RemoveAll(work)
		return ErrUnavailable
	}
	out, childOut, err := os.Pipe()
	if err != nil {
		_ = in.Close()
		_ = childIn.Close()
		_ = os.RemoveAll(work)
		return ErrUnavailable
	}
	cmd := exec.CommandContext(w.ctx, w.command.Path, w.command.Args...)
	cmd.Dir, cmd.Env = work, isolatedEnvironment(work)
	// Using explicit OS pipes lets Wait reap an idle crashed worker without
	// closing a response pipe before its final bytes have been consumed.
	cmd.Stdin, cmd.Stdout = childIn, childOut
	err = cmd.Start()
	_ = childIn.Close()
	_ = childOut.Close()
	if err != nil {
		_ = in.Close()
		_ = out.Close()
		_ = os.RemoveAll(work)
		return ErrUnavailable
	}
	p := &workerProcess{cmd: cmd, in: in, out: out, reader: bufio.NewReaderSize(out, maxFrame+1), done: make(chan struct{}), dir: work}
	w.process = p
	go func() { _ = cmd.Wait(); close(p.done) }()
	return nil
}

// os.Pipe returns the read end first; the parent writes classifier requests.
func workerInput() (*os.File, *os.File, error) {
	read, write, err := os.Pipe()
	return write, read, err
}

func readFrame(p *workerProcess, value any) error {
	line, err := p.reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > maxFrame {
		return ErrOutput
	}
	if err != nil {
		return ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrOutput
	}
	return nil
}

func (w *Worker) Classify(ctx context.Context, request Request) (Result, error) {
	// The engine already admits one inference per process. Direct users cannot
	// create a second queue by calling this implementation concurrently.
	if !w.mu.TryLock() {
		return Result{}, ErrUnavailable
	}
	defer w.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, boundedTimeout(w.command.Timeout))
	defer cancel()
	if w.ctx.Err() != nil {
		return Result{}, ErrUnavailable
	}
	if ctx.Err() != nil {
		return Result{}, inferenceContextError(ctx)
	}
	if w.process != nil {
		select {
		case <-w.process.done:
			w.discard()
		default:
		}
	}
	w.serial++
	id := w.serial
	frame, err := json.Marshal(struct {
		ID      uint64  `json:"id"`
		Request Request `json:"request"`
	}{id, request})
	if err != nil || len(frame)+1 > maxFrame {
		return Result{}, ErrOutput
	}
	fresh := w.process == nil
	if fresh {
		if err := w.start(); err != nil {
			return Result{}, err
		}
	}
	p := w.process
	type response struct {
		ID     uint64  `json:"id"`
		Result *Result `json:"result"`
		Error  string  `json:"error"`
	}
	type completed struct {
		response response
		err      error
	}
	done := make(chan completed, 1)
	go func() {
		var reply response
		err := func() error {
			if fresh {
				var ready struct {
					Ready bool `json:"ready"`
				}
				if err := readFrame(p, &ready); err != nil {
					return err
				}
				if !ready.Ready {
					return ErrOutput
				}
			}
			if _, err := p.in.Write(append(frame, '\n')); err != nil {
				return ErrUnavailable
			}
			return readFrame(p, &reply)
		}()
		done <- completed{reply, err}
	}()
	select {
	case <-ctx.Done():
		w.discard()
		<-done // No late response can be consumed by a later request.
		return Result{}, inferenceContextError(ctx)
	case <-w.ctx.Done():
		w.discard()
		<-done
		return Result{}, ErrUnavailable
	case result := <-done:
		if ctx.Err() != nil || w.ctx.Err() != nil {
			w.discard()
			return Result{}, inferenceContextError(ctx)
		}
		if result.err != nil {
			w.discard()
			return Result{}, result.err
		}
		reply := result.response
		if reply.ID != id || (reply.Error != "" && reply.Result != nil) {
			w.discard()
			return Result{}, ErrOutput
		}
		if reply.Error == "classification_failed" && reply.Result == nil {
			return Result{}, ErrUnavailable
		}
		if reply.Error != "" || reply.Result == nil || Validate(request, *reply.Result) != nil {
			w.discard()
			return Result{}, ErrOutput
		}
		return *reply.Result, nil
	}
}

func inferenceContextError(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ErrTimeout
	}
	return ErrUnavailable
}
