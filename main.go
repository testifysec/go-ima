package main

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type measurment struct {
	pcrBank       int
	pcrChecksum   []byte
	imaPolicyName string
	hashAlgo      string
	fileChecksum  []byte
	fileName      string
}

const imaFile = "/sys/kernel/security/integrity/ima/ascii_runtime_measurements"

func main() {
	fileToCheck := os.Args[1]

	f, err := os.Open(imaFile)
	if err != nil {
		log.Fatalf("Error reading IMA file, %v", err)
	}
	defer f.Close()

	measurments := []measurment{}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		pcrBank, err := strconv.Atoi(fields[0])
		if err != nil {
			log.Fatalf("Error reading IMA file, %v", err)
		}

		pcrChecksum := []byte(fields[1])
		imaPolicyName := fields[2]
		algocheck := strings.Split(fields[3], ":")
		if len(algocheck) < 2 {
			if err != nil {
				log.Fatalf("Error reading IMA file, algohash array to short")
			}
		}
		algo := algocheck[0]

		checksum := []byte(algocheck[1])
		fileName := fields[4]

		newMeasurment := measurment{
			pcrBank:       pcrBank,
			pcrChecksum:   pcrChecksum,
			imaPolicyName: imaPolicyName,
			hashAlgo:      algo,
			fileChecksum:  checksum,
			fileName:      fileName,
		}
		measurments = append(measurments, newMeasurment)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	if err = validateFile(fileToCheck, measurments); err != nil {
		log.Fatalf("Validation Erorr: %v", err)
	} else {
		os.Exit(0)
	}
}

//check return an eror if validation fails
func validateFile(fn string, ms []measurment) error {
	inMemory := false
	checksumError := false
	f, err := os.Open(fn)
	if err != nil {
		log.Fatalf("Error reading IMA file, %v", err)
	}
	defer f.Close()

	fileToCheck, err := filepath.Abs(f.Name())
	if err != nil {
		log.Fatalf("Error reading IMA file, %v", err)
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatalf("Error reading IMA file, %v", err)
	}

	data := []byte{}
	f.Read(data)
	shasum := h.Sum(nil)

	for _, m := range ms {
		if m.fileName == fileToCheck {
			inMemory = true
			disk := fmt.Sprintf("%x", shasum)
			ima := string(m.fileChecksum)
			if ima != disk {
				fmt.Printf("Disk: %x\n", shasum)
				fmt.Printf("IMA : %s\n", m.fileChecksum)
				checksumError = true
			}

		}
	}
	if checksumError {
		return errors.New("checksum error")
	}

	if !inMemory {
		return errors.New("not in memory")
	}
	return nil
}
