package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

const (
	zipFileExt  = ".zip"
	passwordEnv = "PASSWORD"
)

type config struct {
	Input    string
	Output   string
	Password string
	Unzip    bool
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetPrefix("bizip: ")

	config, err := parseFlags()
	if err != nil {
		log.Fatal(err)
	}

	err = unzipInputFiles(config)
	if err != nil {
		log.Fatal(err)
	}
}

func parseFlags() (config, error) {
	input := flag.String("input", "", "a glob pattern for input zip files that will be unzipped and combined.")
	output := flag.String("output", "", "path to output file.")
	encrypted := flag.Bool("encrypted", false, "indicates if the input zip files are encrypted. The password should be stored in the PASSWORD environment variable.")
	unzip := flag.Bool("unzip", false, "indicates if the output file should be unzipped.")

	flag.Usage = func() {
		fmt.Println("bizip unzips and combines zip files that are the outputs by Binalyze products as a single output file. If the input zip files are encrypted (and the '--unzip' flag is not set), the output zip file will be encrypted as well.")
		fmt.Println("flags:")
		flag.PrintDefaults()
		fmt.Println("example usage:")
		fmt.Println("  ./bizip --encrypted --input ./data/input.*.zip --output ./data/output --unzip")
	}

	flag.Parse()

	cfg := config{
		Input:  *input,
		Output: *output,
		Unzip:  *unzip,
	}

	if len(cfg.Input) == 0 {
		return cfg, errors.New("input flag is missing")
	}

	if len(cfg.Output) == 0 {
		return cfg, errors.New("output flag is missing")
	}
	if !*unzip && !strings.HasSuffix(cfg.Output, zipFileExt) {
		cfg.Output += zipFileExt
	}

	if *encrypted {
		cfg.Password = os.Getenv(passwordEnv)
	}

	return cfg, nil
}
