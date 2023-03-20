package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/binalyze/bizip"
)

const (
	zipFileExt  = ".zip"
	passwordEnv = "PASSWORD"
)

type config struct {
	input    string
	output   string
	password string
	unzip    bool
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetPrefix("bizip: ")

	cfg, err := parseFlags()
	if err != nil {
		log.Fatal(err)
	}

	bizipCfg, err := bizip.NewConfig(
		cfg.input,
		cfg.output,
		cfg.password,
		cfg.unzip,
		log.Printf,
		nil,
	)
	if err != nil {
		log.Fatal(err)
	}

	err = bizip.UnzipInputFiles(bizipCfg)
	if err != nil {
		log.Fatal(err)
	}
}

func parseFlags() (config, error) {
	input := flag.String("input", "", "a glob pattern for input zip files that will be unzipped and combined.")
	output := flag.String("output", "", "path to output file.")
	encrypted := flag.Bool("encrypted", false, "indicates if the input zip files are encrypted. The password should "+
		"be stored in the PASSWORD environment variable.")
	unzip := flag.Bool("unzip", false, "indicates if the output file should be unzipped.")

	flag.Usage = func() {
		fmt.Println("bizip unzips and combines zip files that are the outputs by Binalyze products as a single " +
			"output file. If the input zip files are encrypted (and the '--unzip' flag is not set), the output zip " +
			"file will be encrypted as well.")
		fmt.Println("flags:")
		flag.PrintDefaults()
		fmt.Println("example usage:")
		fmt.Println("  ./bizip --encrypted --input ./data/input.*.zip --output ./data/output --unzip")
	}

	flag.Parse()

	cfg := config{
		input:  *input,
		output: *output,
		unzip:  *unzip,
	}

	if len(cfg.input) == 0 {
		return cfg, fmt.Errorf("input flag is required")
	}

	if len(cfg.output) == 0 {
		return cfg, fmt.Errorf("output flag is required")
	}
	if !cfg.unzip && !strings.HasSuffix(cfg.output, zipFileExt) {
		cfg.output += zipFileExt
	}

	if *encrypted {
		cfg.password = os.Getenv(passwordEnv)
	}

	return cfg, nil
}
