package bizip

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/alexmullins/zip"
)

const zipFileExt = ".zip"

const bufioSize = 1 * 1024 * 1024

type LogFunc func(format string, v ...interface{})
type ProgressFunc func(unzipped, total int)

// Bizip is a struct that contains all the necessary information to unzip files.
type Bizip struct {
	Input    string
	Output   string
	Password string
	Unzip    bool
	Log      LogFunc
	Progress ProgressFunc
	rdbuf    *bufio.Reader
	wrbuf    *bufio.Writer
}

// UnzipFiles unzips files.
func (bz *Bizip) UnzipFiles(ctx context.Context) error {
	if err := bz.init(); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}

	inputs, err := findInputZipFiles(bz.Input)
	if err != nil {
		return err
	}
	totalInput := len(inputs)
	bz.Log("%d input zip files found.", totalInput)

	err = validateInputZipFiles(inputs)
	if err != nil {
		return err
	}

	outputName, _, _, err := splitInputZipFilename(inputs[0])
	if err != nil {
		return err
	}

	outputWriter, closer, err := bz.createOutputWriter(outputName)
	if err != nil {
		return err
	}

	md5Hash := md5.New()
	sha1Hash := sha1.New()
	sha256Hash := sha256.New()

	multiWriter := io.MultiWriter(
		&contextWriter{ctx: ctx, w: outputWriter},
		md5Hash,
		sha1Hash,
		sha256Hash,
	)

	bz.Log("Processing...")
	var numProcessed int
	for _, input := range inputs {
		if ctx.Err() != nil {
			_ = closer()
			return ctx.Err()
		}

		err := bz.unzipInputToOutput(input, multiWriter)
		if err != nil {
			_ = closer()
			return err
		}

		numProcessed++
		bz.Log("%d/%d of input zip files processed", numProcessed, totalInput)

		if bz.Progress != nil {
			bz.Progress(numProcessed, totalInput)
		}
	}

	err = closer()
	if err != nil {
		return fmt.Errorf("failed to close output file. error: %w", err)
	}
	bz.Log("Unzip completed, created '%s'", bz.Output)

	bz.Log("Hashes:")
	bz.Log("md5: '%s'", hashToString(md5Hash))
	bz.Log("sha1: '%s'", hashToString(sha1Hash))
	bz.Log("sha256: '%s'", hashToString(sha256Hash))

	return nil
}

func (bz *Bizip) init() error {
	if len(bz.Input) == 0 {
		return errors.New("input is required")
	}
	if len(bz.Output) == 0 {
		return errors.New("output is required")
	}
	if bz.Log == nil {
		bz.Log = func(_ string, _ ...interface{}) {}
	}
	bz.rdbuf = bufio.NewReaderSize(nil, bufioSize)
	bz.wrbuf = bufio.NewWriterSize(nil, bufioSize)
	return nil
}

func (bz *Bizip) createOutputWriter(outputName string) (io.Writer, func() error, error) {
	// We shouldn't overwrite existing file.
	outputFile, err := os.OpenFile(bz.Output, os.O_EXCL|os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create output file. path: '%s' error: %w", bz.Output, err)
	}

	if bz.Unzip {
		closer := func() error {
			err := outputFile.Close()
			if err != nil {
				return fmt.Errorf("failed to close output file. path: '%s' error: %w", bz.Output, err)
			}
			return nil
		}
		return outputFile, closer, nil
	}

	zipWriter := zip.NewWriter(outputFile)

	zipEntry, err := createZipEntry(zipWriter, outputName, bz.Password)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create zip entry. path: '%s' zip entry: '%s' error: '%s'", bz.Output, outputName, err)
	}

	closer := func() error {
		errZip := zipWriter.Close()
		if errZip != nil {
			errZip = fmt.Errorf("failed to close zip writer. path: '%s' zip entry: '%s' error: %w", bz.Output, outputName, errZip)
		}

		errFile := outputFile.Close()
		if errFile != nil {
			errFile = fmt.Errorf("failed to close output file. path: '%s' error: %w", bz.Output, errFile)
		}

		if errZip != nil {
			return errZip
		}
		return errFile
	}
	return zipEntry, closer, nil
}

func (bz *Bizip) unzipInputToOutput(input string, output io.Writer) error {
	inputFile, err := os.Open(input)
	if err != nil {
		return err
	}
	defer inputFile.Close()

	inputReader, err := bz.createUnzipReader(inputFile)
	if err != nil {
		return err
	}
	defer inputReader.Close()

	bz.rdbuf.Reset(inputReader)
	defer bz.rdbuf.Reset(nil)

	bz.wrbuf.Reset(output)
	defer bz.wrbuf.Reset(nil)

	_, err = io.Copy(bz.wrbuf, bz.rdbuf)
	if err != nil {
		return err
	}
	return bz.wrbuf.Flush()
}

func (bz *Bizip) createUnzipReader(file *os.File) (io.ReadCloser, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat file. path: '%s' error: %w", file.Name(), err)
	}

	size := info.Size()

	zipReader, err := zip.NewReader(file, size)
	if err != nil {
		return nil, err
	}
	if len(zipReader.File) == 0 {
		return nil, fmt.Errorf("zip file '%s' has no entries", file.Name())
	}

	zipFile := zipReader.File[0]

	if bz.Password != "" {
		zipFile.SetPassword(bz.Password)
	}
	return zipFile.Open()
}

func findInputZipFiles(pattern string) ([]string, error) {
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("failed to find input zip files. pattern: '%s'", pattern)
	}
	return files, nil
}

func createZipEntry(zipWriter *zip.Writer, name, password string) (io.Writer, error) {
	if password != "" {
		return zipWriter.Encrypt(name, password)
	}
	return zipWriter.Create(name)
}

func validateInputZipFiles(inputs []string) error {
	for loopIndex, input := range inputs {
		info, err := os.Lstat(input)
		if err != nil {
			return err
		}

		if !info.Mode().IsRegular() {
			return fmt.Errorf("input zip file is not a regular file. path: '%s'", input)
		}

		name, index, ext, err := splitInputZipFilename(input)
		if err != nil {
			return err
		}

		if len(name) == 0 {
			return fmt.Errorf("input zip file has an invalid filename. path: '%s'", input)
		}

		expectedIndex := loopIndex + 1
		actualIndex, err := strconv.Atoi(index)
		if err != nil {
			return fmt.Errorf("input zip file has a invalid index. index: '%s' path: '%s'", index, input)
		}
		if actualIndex != expectedIndex {
			return fmt.Errorf("input zip file has an unexpected index. expected index: %d actual index: %d path: '%s'", expectedIndex, actualIndex, input)
		}

		if ext != zipFileExt {
			return fmt.Errorf("input zip file doesn't have '%s' extension. path: '%s'", zipFileExt, input)
		}
	}
	return nil
}

func splitInputZipFilename(input string) (name string, index string, ext string, err error) {
	base := filepath.Base(input)

	parts := strings.Split(base, ".")
	if len(parts) >= 3 {
		name = strings.Join(parts[:len(parts)-2], ".")
		index = parts[len(parts)-2]
		ext = "." + parts[len(parts)-1]
	}
	if name == "" || index == "" || ext == "" {
		err = fmt.Errorf("input zip file has an invalid file name. path: '%s'", input)
	}
	return
}

func hashToString(algorithm hash.Hash) string {
	return hex.EncodeToString(algorithm.Sum(nil))
}

type contextWriter struct {
	ctx context.Context
	w   io.Writer
}

func (cw *contextWriter) Write(p []byte) (n int, err error) {
	if cw.ctx.Err() != nil {
		return 0, cw.ctx.Err()
	}
	return cw.w.Write(p)
}
