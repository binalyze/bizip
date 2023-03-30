# bizip

bizip is a command-line tool that allows users to unzip and combine zip files that are generated by Binalyze InterACT image command.

This tool is not for general-purpose zip file processing.

# Installation

You can download the latest release of bizip from the [releases](https://github.com/binalyze/bizip/releases) section. Alternatively, you can install it from the source by running the following command in your terminal, if you are familiar with Go programming language.

```bash
go install github.com/binalyze/bizip/cmd/bizip@latest
```

# Usage

After installing bizip, you can use it to unzip and combine zip files by running the following command in your terminal:

## With Encryption (Unixes):

```shell
export PASSWORD="your_password"
./bizip --encrypted --unzip --input "inputs/image*.zip" --output output_file_path
```

## Without Encryption (Unixes):

```shell
./bizip --unzip --input "inputs/image*.zip" --output output_file_path
```

## With Encryption (Windows):

cmd.exe:
```
set PASSWORD=your_password
bizip.exe --unzip --encrypted --input "inputs/image*.zip" --output output_file_path
```

PowerShell:
```powershell
$env:PASSWORD = 'your_password'
.\bizip.exe --unzip --encrypted --input "inputs/image*.zip" --output output_file_path
```

## Flags

- `--encrypted`: If this flag is set, the input zip files are expected to be encrypted zip files. The password for decryption should be stored in the `PASSWORD` environment variable.
- `--input`: The input zip files should be specified specified using the glob pattern. For example, "inputs/image*.zip" will match all files under inputs folder having image prefix with .zip file extension. Note that, matched files are sorted before processing.
- `--output`: The output file path.
- `--unzip`: If this flag is set, the output file will not be a zip file. If this flag is not set and the input zip files are encrypted, the output file will also be an encrypted zip file.

## Help

To view a detailed help message, run the following command in your terminal:

```bash
./bizip --help
```

# License

bizip is licensed under the [Apache License](LICENSE).
