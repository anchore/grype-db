package tarutil

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/klauspost/compress/zstd"
)

var ErrUnsupportedArchiveSuffix = fmt.Errorf("archive name has an unsupported suffix")

var _ Writer = (*writer)(nil)

type writer struct {
	compressor io.WriteCloser
	writer     *tar.Writer
}

// NewWriter creates a new tar writer that writes to the specified archive path. Supports .tar.gz, .tar.zst, .tar.xz, and .tar file extensions.
func NewWriter(archivePath string) (Writer, error) {
	w, err := newCompressor(archivePath)
	if err != nil {
		return nil, err
	}

	tw := tar.NewWriter(w)

	return &writer{
		compressor: w,
		writer:     tw,
	}, nil
}

func newCompressor(archivePath string) (io.WriteCloser, error) {
	archive, err := os.Create(archivePath)
	if err != nil {
		return nil, err
	}

	switch {
	case strings.HasSuffix(archivePath, ".tar.gz"):
		return gzip.NewWriter(archive), nil
	case strings.HasSuffix(archivePath, ".tar.zst"):
		// adding zstd options for better compression
		w, err := zstd.NewWriter(archive, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
		if err != nil {
			return nil, fmt.Errorf("unable to get zst compression stream: %w", err)
		}
		return w, nil
	case strings.HasSuffix(archivePath, ".tar.xz"):
		// use xz for compression via an external process
		cmd := exec.Command("xz", "-9", "--threads=0", "-c")
		cmd.Stdout = archive
		cmd.Stderr = os.Stderr

		pipe, err := cmd.StdinPipe()
		if err != nil {
			return nil, fmt.Errorf("unable to create xz stdin pipe: %w", err)
		}

		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("unable to start xz process: %w", err)
		}

		// return a WriteCloser that handles the xz process
		return &xzCompressor{
			cmd:  cmd,
			pipe: pipe,
		}, nil
	case strings.HasSuffix(archivePath, ".tar"):
		return archive, nil
	}
	return nil, ErrUnsupportedArchiveSuffix
}

// xzCompressor wraps the stdin pipe of the xz process and ensures proper cleanup.
type xzCompressor struct {
	cmd  *exec.Cmd
	pipe io.WriteCloser
}

func (x *xzCompressor) Write(p []byte) (int, error) {
	return x.pipe.Write(p)
}

func (x *xzCompressor) Close() error {
	if err := x.pipe.Close(); err != nil {
		return fmt.Errorf("unable to close xz stdin pipe: %w", err)
	}
	if err := x.cmd.Wait(); err != nil {
		return fmt.Errorf("xz process error: %w", err)
	}
	return nil
}

func (w *writer) WriteEntry(entry Entry) error {
	return entry.writeEntry(w.writer)
}

func (w *writer) Close() error {
	if w.writer != nil {
		err := w.writer.Close()
		w.writer = nil
		if err != nil {
			return fmt.Errorf("unable to close tar writer: %w", err)
		}
	}

	if w.compressor != nil {
		err := w.compressor.Close()
		w.compressor = nil
		return err
	}

	return nil
}

// type writer struct {
//	compressor io.WriteCloser
//	writer     *tar.Writer
//	spy        *writeSpy
//}
//
//// NewWriter creates a new tar writer that writes to the specified archive path. Supports .tar.gz, .tar.zst, .tar.xz, and .tar file extensions.
// func NewWriter(archivePath string) (Writer, error) {
//	w, spy, err := newCompressor(archivePath)
//	if err != nil {
//		return nil, err
//	}
//
//	tw := tar.NewWriter(w)
//
//	return &writer{
//		compressor: w,
//		writer:     tw,
//		spy:        spy,
//	}, nil
//}
//
// func newCompressor(archivePath string) (io.WriteCloser, *writeSpy, error) {
//	archive, err := os.Create(archivePath)
//	if err != nil {
//		return nil, nil, err
//	}
//
//	var baseWriter io.WriteCloser
//	switch {
//	case strings.HasSuffix(archivePath, ".tar.gz"):
//		baseWriter = gzip.NewWriter(archive)
//	case strings.HasSuffix(archivePath, ".tar.zst"):
//		// adding zstd.WithWindowSize(zstd.MaxWindowSize), zstd.WithAllLitEntropyCompression(true)
//		// will have slightly better results, but use a lot more memory
//		w, err := zstd.NewWriter(archive, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
//		if err != nil {
//			return nil, nil, fmt.Errorf("unable to get zst compression stream: %w", err)
//		}
//		baseWriter = w
//	case strings.HasSuffix(archivePath, ".tar.xz"):
//		// Use xz for compression via an external process
//		cmd := exec.Command("xz", "-9", "--threads=0", "-c")
//		cmd.Stdout = archive
//		cmd.Stderr = os.Stderr
//
//		pipe, err := cmd.StdinPipe()
//		if err != nil {
//			return nil, nil, fmt.Errorf("unable to create xz stdin pipe: %w", err)
//		}
//
//		if err := cmd.Start(); err != nil {
//			return nil, nil, fmt.Errorf("unable to start xz process: %w", err)
//		}
//
//		xz := &xzCompressor{
//			cmd:  cmd,
//			pipe: pipe,
//			done: make(chan struct{}),
//		}
//
//		baseWriter = xz
//	case strings.HasSuffix(archivePath, ".tar"):
//		baseWriter = archive
//	default:
//		return nil, nil, ErrUnsupportedArchiveSuffix
//	}
//
//	spy := newWriteSpy(baseWriter, sizer(archivePath))
//	return spy, spy, nil
//}
//
//func sizer(path string) func() int64 {
//	return func() int64 {
//		stat, err := os.Stat(path)
//		if err != nil {
//			return 0
//		}
//		return stat.Size()
//	}
//}
//
//// writeSpy wraps an io.WriteCloser to track the number of bytes written.
//type writeSpy struct {
//	writer io.WriteCloser
//	mu     sync.Mutex
//	total  int64
//	done   <-chan struct{}
//	sizer  func() int64
//}
//
//func newWriteSpy(w io.WriteCloser, sizer func() int64) *writeSpy {
//	var done <-chan struct{}
//	if xz, ok := w.(*xzCompressor); ok {
//		done = xz.done
//	} else {
//		// Create a dummy channel for non-xz writers
//		ch := make(chan struct{})
//		close(ch)
//		done = ch
//	}
//
//	spy := &writeSpy{
//		writer: w,
//		done:   done,
//		sizer:  sizer,
//	}
//
//	// Start the progress logger
//	go spy.logProgress()
//
//	return spy
//}
//
//func (s *writeSpy) Write(p []byte) (int, error) {
//	n, err := s.writer.Write(p)
//	s.mu.Lock()
//	s.total += int64(n)
//	s.mu.Unlock()
//	return n, err
//}
//
//func (s *writeSpy) Close() error {
//	return s.writer.Close()
//}
//
//func (s *writeSpy) logProgress() {
//	ticker := time.NewTicker(5 * time.Second)
//	defer ticker.Stop()
//
//	logProgress := func() {
//		s.mu.Lock()
//		log.WithFields("db-size", humanize.Bytes(uint64(s.total)), "archive-size", humanize.Bytes(uint64(s.sizer()))).Debug("archive write status")
//		s.mu.Unlock()
//	}
//
//	for {
//		select {
//		case <-ticker.C:
//			logProgress()
//		case <-s.done:
//			logProgress()
//			return
//		}
//	}
//}
//
//func (w *writer) WriteEntry(entry Entry) error {
//	return entry.writeEntry(w.writer)
//}
//
//func (w *writer) Close() error {
//	if w.writer != nil {
//		err := w.writer.Close()
//		w.writer = nil
//		if err != nil {
//			return fmt.Errorf("unable to close tar writer: %w", err)
//		}
//	}
//
//	if w.compressor != nil {
//		err := w.compressor.Close()
//		w.compressor = nil
//		return err
//	}
//
//	return nil
//}
//
//// xzCompressor wraps the stdin pipe of the xz process and ensures proper cleanup.
//type xzCompressor struct {
//	cmd  *exec.Cmd
//	pipe io.WriteCloser
//	done chan struct{}
//}
//
//func (x *xzCompressor) Write(p []byte) (int, error) {
//	return x.pipe.Write(p)
//}
//
//func (x *xzCompressor) Close() error {
//	if err := x.pipe.Close(); err != nil {
//		return fmt.Errorf("unable to close xz stdin pipe: %w", err)
//	}
//	if err := x.cmd.Wait(); err != nil {
//		return fmt.Errorf("xz process error: %w", err)
//	}
//	close(x.done) // Signal that the xz process has completed
//	return nil
//}
