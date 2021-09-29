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

	if err = validateFile(fileToCheck, measurments); err != nil {
		fmt.Println("Failed - file has been modified")
	} else {
		fmt.Println("Passed - file has not been modified")
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

}

//check return an eror if validation fails
func validateFile(fn string, ms []measurment) error {
	f, err := os.Open(fn)
	if err != nil {
		log.Fatalf("Error reading IMA file, %v", err)
	}
	defer f.Close()

	fileToCheck, err := filepath.Abs(f.Name())
	if err != nil {
		return err
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}

	data := []byte{}
	f.Read(data)
	shasum := h.Sum(nil)

	for _, m := range ms {
		if m.fileName == fileToCheck {
			if !Equal(shasum, m.fileChecksum) {
				return errors.New("Validation Error")
			}
		}
	}
	return nil
}

func Equal(slice1 []byte, slice2 []byte) bool {
	sl1 := slice1[:]
	if len(sl1) != len(slice2) {
		return false
	}

	for i := range slice1 {
		if sl1[i] != slice2[i] {
			return false
		}
	}
	return true
}
