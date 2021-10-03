package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type measurmentLog struct {
	measurments []measurment
	file        *os.File
	aggr        []byte
}

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
	testHash()
	fileToCheck := os.Args[1]

	f, err := os.Open(imaFile)
	if err != nil {
		log.Fatalf("Error reading IMA file, %v", err)
	}
	defer f.Close()

	mLog := measurmentLog{
		measurments: []measurment{},
		file:        f,
		aggr:        []byte{},
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		pcrBank, err := strconv.Atoi(fields[0])
		if err != nil {
			log.Fatalf("Error reading IMA file, %v", err)
		}

		pcrChecksum, err := hex.DecodeString(fields[1])
		if err != nil {
			log.Fatalf("Error decoding hex string, %v", err)
		}

		imaPolicyName := fields[2]
		algocheck := strings.Split(fields[3], ":")
		if len(algocheck) < 2 {
			if err != nil {
				log.Fatalf("Error reading IMA file, algohash array to short")
			}
		}
		algo := algocheck[0]

		checksum, err := hex.DecodeString(algocheck[1])
		if err != nil {
			log.Fatalf("Error decoding hex string, %v", err)
		}

		fileName := fields[4]

		newMeasurment := measurment{
			pcrBank:       pcrBank,
			pcrChecksum:   pcrChecksum,
			imaPolicyName: imaPolicyName,
			hashAlgo:      algo,
			fileChecksum:  checksum,
			fileName:      fileName,
		}
		mLog.measurments = append(mLog.measurments, newMeasurment)
	}

	mLog.calcAggr()

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	if err = validateFile(fileToCheck, mLog.measurments); err != nil {
		log.Fatalf("Validation Error: %v", err)
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
			if !bytes.Equal(m.fileChecksum, shasum) {
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

func (mL *measurmentLog) calcAggr() {
	runningHash, err := hex.DecodeString("")
	if err != nil {
		log.Fatalf("Error decoding HEX String, %v", err)
	}

	runningHash = []byte{}

	for _, m := range mL.measurments {

		if m.imaPolicyName == "ima-ng" {
			runningHash, err = hex.DecodeString(fmt.Sprintf("%x%x", runningHash, m.fileChecksum))
			if err != nil {
				log.Fatalf("Error decoding HEX String, %v", err)
			}
			h := sha1.Sum(runningHash)
			runningHash = h[:]

		} else {
			fmt.Println(m.imaPolicyName)
		}

	}

	fmt.Printf("%x", runningHash)
}

func testHash() {
	//https://elixir.bootlin.com/linux/v5.14.9/source/security/integrity/ima/ima.h
	//https://stackoverflow.com/questions/10163436/how-can-a-the-extension-of-the-pcr-value-be-replicated-with-e-g-sha1sum

	v := "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
	x := "7c211433f02071597741e6ff5a8ea34789abbf43"
	s := "39955b37b910e57748368b0922fd44fbff72bda5"

	h0, err := hex.DecodeString(s)
	if err != nil {
		log.Fatalf("%v", err)
	}

	h1, err := hex.DecodeString(v)
	if err != nil {
		log.Fatalf("%v", err)
	}

	h2, err := hex.DecodeString(x)
	if err != nil {
		log.Fatalf("%v", err)
	}

	h3 := append(h1, h2...)
	if err != nil {
		log.Fatalf("%v", err)
	}

	h3str := hex.EncodeToString(h3)
	h4 := sha1.Sum([]byte(h3str))

	fmt.Printf("%x\n", h0)
	fmt.Printf("%x\n", h1)
	fmt.Printf("%x\n", h2)
	fmt.Printf("%x\n", h3)
	fmt.Printf("%s\n", hex.EncodeToString(h4[:]))

}
