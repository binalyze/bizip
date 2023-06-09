package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	bz := &bizip.Bizip{
		Input:    cfg.input,
		Output:   cfg.output,
		Password: cfg.password,
		Unzip:    cfg.unzip,
		Log:      log.Printf,
	}

	err = bz.UnzipFiles(ctx)
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
		fmt.Println("  with encryption:")
		fmt.Println("        export PASSWORD=\"your_password\"")
		fmt.Println("        ./bizip --encrypted --input ./data/input.*.zip --output ./data/output --unzip")
		fmt.Println("  without encryption:")
		fmt.Println("        ./bizip --input ./data/input.*.zip --output ./data/output --unzip")
	}

	flag.Parse()

	cfg := config{
		input:  *input,
		output: *output,
		unzip:  *unzip,
	}

	if len(cfg.input) == 0 {
		return cfg, errors.New("input flag is required")
	}
	if len(cfg.output) == 0 {
		return cfg, errors.New("output flag is required")
	}
	if !cfg.unzip && !strings.HasSuffix(cfg.output, zipFileExt) {
		cfg.output += zipFileExt
	}

	if *encrypted {
		cfg.password = os.Getenv(passwordEnv)
		if cfg.password == "" {
			return cfg, fmt.Errorf("password is required when the input zip files are encrypted")
		}
	}
	return cfg, nil
}
