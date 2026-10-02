package cmd

import (
	"bytes"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

var (
	logsFollow bool
	logsLines  int
)

var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "View gateway event logs",
	RunE: func(cmd *cobra.Command, args []string) error {
		follow, _ := cmd.Flags().GetBool("follow")
		lines, _ := cmd.Flags().GetInt("lines")

		home, _ := os.UserHomeDir()
		logPath := filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "events.jsonl")

		tail, offset, err := lastLines(logPath, lines)
		if err != nil {
			return err
		}
		if _, err := os.Stdout.Write(tail); err != nil || !follow {
			return err
		}
		interrupted := make(chan os.Signal, 1)
		signal.Notify(interrupted, os.Interrupt)
		defer signal.Stop(interrupted)
		return followLog(logPath, offset, os.Stdout, interrupted)
	},
}

// lastLines returns the last n lines of a file and the file's size when it
// was read. It reads backwards in chunks, so a large log is not loaded whole,
// and uses no external program: tail does not exist on Windows.
func lastLines(path string, n int) ([]byte, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, 0, err
	}
	size := info.Size()
	if n <= 0 || size == 0 {
		return nil, size, nil
	}
	const chunk = 64 << 10
	var tail []byte
	newlines := 0
	for position := size; position > 0; {
		length := int64(chunk)
		if length > position {
			length = position
		}
		position -= length
		buffer := make([]byte, length)
		if _, err := file.ReadAt(buffer, position); err != nil && err != io.EOF {
			return nil, size, err
		}
		tail = append(buffer, tail...)
		newlines += bytes.Count(buffer, []byte{'\n'})
		// One extra newline bounds the first wanted line; a final newline
		// ends the last line rather than starting another.
		if newlines > n {
			break
		}
	}
	body := tail
	trailing := bytes.HasSuffix(body, []byte{'\n'})
	if trailing {
		body = body[:len(body)-1]
	}
	start := 0
	for i, seen := len(body)-1, 0; i >= 0; i-- {
		if body[i] == '\n' {
			seen++
			if seen == n {
				start = i + 1
				break
			}
		}
	}
	return tail[start:], size, nil
}

// followLog copies what is appended to the log until interrupted, or until
// out stops taking writes.
func followLog(path string, offset int64, out io.Writer, stop <-chan os.Signal) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	sink := &writeErrorKeeper{out: out}
	// The file that offset counts into.
	last, _ := os.Stat(path)
	for {
		select {
		case <-stop:
			return nil
		case <-ticker.C:
		}
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.Size() < offset || (last != nil && !os.SameFile(last, info)) {
			// The log was rotated. Size alone misses a new file that has
			// already grown past the old offset.
			offset = 0
		}
		last = info
		if info.Size() == offset {
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		if _, err := file.Seek(offset, io.SeekStart); err == nil {
			copied, _ := io.Copy(sink, file)
			offset += copied
		}
		file.Close()
		if sink.err != nil {
			// The reader is gone (`logs -f | head -1`). Windows has no
			// SIGPIPE to end the process, so this is the only way out.
			return sink.err
		}
	}
}

// writeErrorKeeper remembers a failed write. io.Copy reports read and write
// errors alike, and a failed read of the log is retried on the next poll.
type writeErrorKeeper struct {
	out io.Writer
	err error
}

func (w *writeErrorKeeper) Write(p []byte) (int, error) {
	n, err := w.out.Write(p)
	if err != nil {
		w.err = err
	}
	return n, err
}

func init() {
	logsCmd.Flags().BoolVarP(&logsFollow, "follow", "f", false, "Follow log output")
	logsCmd.Flags().IntVarP(&logsLines, "lines", "l", 20, "Number of lines to show")
	rootCmd.AddCommand(logsCmd)
}
