package bizip

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/alexmullins/zip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBizip_UnzipFiles(t *testing.T) {
	dir := t.TempDir()

	_, err := createTestZipFile(dir, "test_file.1.zip", "test_file", "", []byte("test_"))
	require.NoError(t, err)

	_, err = createTestZipFile(dir, "test_file.2.zip", "test_file", "", []byte("data"))
	require.NoError(t, err)

	output := filepath.Join(dir, "test_file")

	bz := &Bizip{
		Input:  filepath.Join(dir, "test_file*.zip"),
		Output: output,
		Unzip:  true,
		Log:    func(_ string, _ ...interface{}) {},
	}

	err = bz.UnzipFiles(context.Background())
	require.NoError(t, err)

	data, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, []byte("test_data"), data)
}

func TestFindInputZipFiles(t *testing.T) {
	dir := t.TempDir()

	file, err := createTestFile(dir, "test_file.1.zip")
	require.NoError(t, err)

	tests := []struct {
		name      string
		pattern   string
		expected  []string
		expectErr bool
	}{
		{
			name:    "wihout_an_error",
			pattern: filepath.Join(dir, "test_file*.zip"),
			expected: []string{
				file,
			},
			expectErr: false,
		},
		{
			name:      "with_a_bad_pattern",
			pattern:   "[",
			expectErr: true,
		},
		{
			name:      "with_a_non_existing_pattern",
			pattern:   "a_non_existing_pattern",
			expectErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := findInputZipFiles(tt.pattern)
			if tt.expectErr {
				require.Error(t, err)
				return
			}
			require.Equal(t, tt.expected, actual)
		})
	}
}

func TestValidateInputZipFiles(t *testing.T) {
	dir := t.TempDir()

	invalidFilename, err := createTestFile(dir, "test_file")
	require.NoError(t, err)

	valid, err := createTestFile(dir, "test_file.1.zip")
	require.NoError(t, err)

	withoutName, err := createTestFile(dir, ".1.zip")
	require.NoError(t, err)

	invalidIndex, err := createTestFile(dir, "test_file._.zip")
	require.NoError(t, err)

	unexpectedIndex, err := createTestFile(dir, "test_file.2.zip")
	require.NoError(t, err)

	wrongExt, err := createTestFile(dir, "test_file.1._")
	require.NoError(t, err)

	tests := []struct {
		name      string
		inputs    []string
		expectErr bool
	}{
		{
			name: "with_a_valid_file",
			inputs: []string{
				valid,
			},
			expectErr: false,
		},
		{
			name: "with_a_non_existing_file",
			inputs: []string{
				"a_non_existing_file",
			},
			expectErr: true,
		},
		{
			name: "with_a_non_regular_file",
			inputs: []string{
				dir,
			},
			expectErr: true,
		},
		{
			name: "with_an_invalid_filename",
			inputs: []string{
				invalidFilename,
			},
			expectErr: true,
		},
		{
			name: "without_a_name",
			inputs: []string{
				withoutName,
			},
			expectErr: true,
		},
		{
			name: "with_invalid_index",
			inputs: []string{
				invalidIndex,
			},
			expectErr: true,
		},
		{
			name: "with_unexpected_index",
			inputs: []string{
				unexpectedIndex,
			},
			expectErr: true,
		},
		{
			name: "with_wrong_ext",
			inputs: []string{
				wrongExt,
			},
			expectErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateInputZipFiles(tt.inputs)
			if tt.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestSplitInputZipFilename(t *testing.T) {
	tests := []struct {
		name          string
		filename      string
		expectedName  string
		expectedIndex string
		expectedExt   string
		expectErr     bool
	}{
		{
			name:          "wihout_error",
			filename:      "test_file.1.zip",
			expectedName:  "test_file",
			expectedIndex: "1",
			expectedExt:   ".zip",
			expectErr:     false,
		},
		{
			name:      "with_error",
			filename:  "test_file",
			expectErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, index, ext, err := splitInputZipFilename(tt.filename)
			if tt.expectErr {
				require.Error(t, err)
				return
			}
			require.Equal(t, tt.expectedName, name)
			require.Equal(t, tt.expectedIndex, index)
			require.Equal(t, tt.expectedExt, ext)
		})
	}
}

func TestCreateOutputWriter(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name     string
		bz       Bizip
		expected []byte
	}{
		{
			name: "without_unzip",
			bz: Bizip{
				Output: filepath.Join(dir, "test_file"),
				Unzip:  false,
				Log:    func(_ string, _ ...interface{}) {},
			},
			expected: []byte("test data"),
		},
		{
			name: "with_unzip",
			bz: Bizip{
				Output: filepath.Join(dir, "test_file.zip"),
				Unzip:  true,
				Log:    func(_ string, _ ...interface{}) {},
			},
			expected: []byte("test_data"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputWriter, closeOutputWriter, err := tt.bz.createOutputWriter("test_file")
			require.NoError(t, err)

			_, err = outputWriter.Write(tt.expected)
			assert.NoError(t, err)

			err = closeOutputWriter()
			require.NoError(t, err)

			if tt.bz.Unzip {
				actual, err := os.ReadFile(tt.bz.Output)
				require.NoError(t, err)
				require.Equal(t, tt.expected, actual)
				return
			}

			outputFile, err := os.Open(tt.bz.Output)
			require.NoError(t, err)

			unzipReader, err := tt.bz.createUnzipReader(outputFile)
			assert.NoError(t, err)

			actual, err := io.ReadAll(unzipReader)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, actual)

			err = outputFile.Close()
			require.NoError(t, err)
		})
	}
}

func TestUnzipInputToOutput(t *testing.T) {
	tests := []struct {
		name     string
		expected []byte
		password string
	}{
		{
			name:     "without_encryption",
			expected: []byte("test_data"),
			password: "",
		},
		{
			name:     "with_encryption",
			expected: []byte("test_data"),
			password: "def",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			input, err := createTestZipFile(dir, "test_file_1.zip", "test_file", test.password, test.expected)
			require.NoError(t, err)

			output := bytes.NewBuffer(nil)
			bz := &Bizip{
				Password: test.password,
				rdbuf:    bufio.NewReader(nil),
				wrbuf:    bufio.NewWriter(nil),
			}

			err = bz.unzipInputToOutput(input, output)
			require.NoError(t, err)
			actual := output.Bytes()
			require.Equal(t, test.expected, actual)
		})
	}
}

func TestHashToString(t *testing.T) {
	expected := "900150983cd24fb0d6963f7d28e17f72" // calculated with 'echo -n abc | md5' command

	md5hash := md5.New()
	md5hash.Write([]byte("abc"))

	actual := hashToString(md5hash)
	require.Equal(t, expected, actual)
}

func createTestZipFile(dir, name, entry, password string, data []byte) (string, error) {
	path := filepath.Join(dir, name)

	zipFile, err := os.Create(path)
	if err != nil {
		return "", err
	}

	zipWriter := zip.NewWriter(zipFile)

	zipEntry, err := createZipEntry(zipWriter, entry, password)
	if err != nil {
		_ = zipFile.Close()
		return "", err
	}

	_, err = zipEntry.Write(data)
	if err != nil {
		_ = zipFile.Close()
		return "", err
	}

	err = zipWriter.Close()
	if err != nil {
		_ = zipFile.Close()
		return "", err
	}
	return zipFile.Name(), zipFile.Close()
}

func createTestFile(dir, name string) (string, error) {
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		return "", err
	}
	_ = f.Close()
	return f.Name(), nil
}
