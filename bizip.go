package bizip

import (
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

type LogFunc func(format string, v ...interface{})
type ProgressFunc func(unzipped, total int)

type Config struct {
	Input    string
	Output   string
	Password string
	Unzip    bool
	Log      LogFunc
	Progress ProgressFunc
}

func NewConfig(input, output, password string, unzip bool, log LogFunc, progress ProgressFunc) (Config, error) {
	cfg := Config{
		Input:    input,
		Output:   output,
		Password: password,
		Unzip:    unzip,
		Log:      log,
		Progress: progress,
	}

	if len(cfg.Input) == 0 {
		return cfg, errors.New("input is required")
	}

	if len(cfg.Output) == 0 {
		return cfg, errors.New("output is required")
	}

	if cfg.Log == nil {
		cfg.Log = func(_ string, _ ...interface{}) {}
	}

	return cfg, nil
}

func UnzipInputFiles(cfg Config) error {
	inputs, err := findInputZipFiles(cfg.Input)
	if err != nil {
		return err
	}
	totalInputCount := len(inputs)
	cfg.Log("%d input zip files found.", totalInputCount)

	err = validateInputZipFiles(inputs)
	if err != nil {
		return err
	}

	outputName, _, _, err := splitInputZipFilename(inputs[0])
	if err != nil {
		return err
	}

	outputWriter, closeOutputWriter, err := createOutputWriter(cfg, outputName)
	if err != nil {
		return err
	}

	md5Hash := md5.New()
	sha1Hash := sha1.New()
	sha256Hash := sha256.New()

	multiWriter := io.MultiWriter(outputWriter, md5Hash, sha1Hash, sha256Hash)

	cfg.Log("Processing...")
	var unzippedInputCount int
	for _, input := range inputs {
		err := unzipInputToOutput(input, cfg.Password, multiWriter)
		if err != nil {
			_ = closeOutputWriter()
			return err
		}

		unzippedInputCount++
		cfg.Log("%d/%d of input zip file processed.", unzippedInputCount, totalInputCount)

		if cfg.Progress != nil {
			cfg.Progress(unzippedInputCount, totalInputCount)
		}
	}

	err = closeOutputWriter()
	if err != nil {
		return fmt.Errorf("failed to close output file. error: %w", err)
	}
	cfg.Log("Process completed, %s created.", cfg.Output)

	cfg.Log("Hashes:")
	cfg.Log("md5: '%s'", hashToString(md5Hash))
	cfg.Log("sha1: '%s'", hashToString(sha1Hash))
	cfg.Log("sha256: '%s'", hashToString(sha256Hash))

	return nil
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

func splitInputZipFilename(input string) (string, string, string, error) {
	base := filepath.Base(input)

	segments := strings.Split(base, ".")
	if len(segments) != 3 {
		return "", "", "", fmt.Errorf("input zip file has an invalid filename. path: '%s'", input)
	}

	name := segments[0]
	index := segments[1]
	ext := "." + segments[2]

	return name, index, ext, nil
}

func createOutputWriter(cfg Config, outputName string) (io.Writer, func() error, error) {
	outputFile, err := os.OpenFile(cfg.Output, os.O_EXCL|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create output file. path: '%s' error: %w", cfg.Output, err)
	}

	if cfg.Unzip {
		closeOutputFile := func() error {
			err := outputFile.Close()
			if err != nil {
				return fmt.Errorf("failed to close output file. path: '%s' error: %w", cfg.Output, err)
			}

			return nil
		}

		return outputFile, closeOutputFile, nil
	}

	zipWriter := zip.NewWriter(outputFile)

	zipEntry, err := createZipEntry(zipWriter, outputName, cfg.Password)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create zip entry. path: '%s' zip entry: '%s' error: '%s'", cfg.Output, outputName, err)
	}

	closeOutputWriter := func() error {
		errZipWriter := zipWriter.Close()
		if errZipWriter != nil {
			errZipWriter = fmt.Errorf("failed to close zip writer. path: '%s' zip entry: '%s' error: %w", cfg.Output, outputName, errZipWriter)
		}

		errOutputFile := outputFile.Close()
		if errOutputFile != nil {
			errOutputFile = fmt.Errorf("failed to close output file. path: '%s' error: %w", cfg.Output, errOutputFile)
		}

		if errZipWriter != nil {
			return errZipWriter
		}

		return errOutputFile
	}

	return zipEntry, closeOutputWriter, nil
}

func createZipEntry(zipWriter *zip.Writer, name, password string) (io.Writer, error) {
	if len(password) > 0 {
		return zipWriter.Encrypt(name, password)
	}

	return zipWriter.Create(name)
}

func unzipInputToOutput(input, password string, outputWriter io.Writer) error {
	inputFile, err := os.Open(input)
	if err != nil {
		return err
	}
	defer inputFile.Close()

	inputReader, err := createUnzipReader(inputFile, password)
	if err != nil {
		return err
	}
	defer inputReader.Close()

	_, err = io.Copy(outputWriter, inputReader)

	return err
}

func createUnzipReader(file *os.File, password string) (io.ReadCloser, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat file. path: '%s' error: %w", file.Name(), err)
	}

	size := info.Size()

	zipReader, err := zip.NewReader(file, size)
	if err != nil {
		return nil, err
	}

	zipFile := zipReader.File[0]

	if len(password) > 0 {
		zipFile.SetPassword(password)
	}

	return zipFile.Open()
}

func hashToString(algorithm hash.Hash) string {
	return hex.EncodeToString(algorithm.Sum(nil))
}
