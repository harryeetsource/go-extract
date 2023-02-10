package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/Velocidex/go-pe"
)

const MB = 1024 * 1024
const maxFileSize = 100 * MB

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: extract_pe [filepath]")
		os.Exit(1)
	}

	filepath := os.Args[1]
	f, err := os.Open(filepath)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	fileInfo, err := f.Stat()
	if err != nil {
		fmt.Printf("Error getting file info: %v\n", err)
		os.Exit(1)
	}
	fileSize := fileInfo.Size()

	if fileSize > maxFileSize {
		fmt.Printf("File size is larger than %d MB, skipping\n", maxFileSize/MB)
		os.Exit(0)
	}

	peFile, err := pe.NewPEFile(filepath)
	if err != nil {
		fmt.Printf("Error creating PE file: %v\n", err)
		os.Exit(1)
	}

	var offset int64
	offset = 0
	for {
		peSignature := make([]byte, 4)
		_, err = f.ReadAt(peSignature, offset)
		if err != nil {
			break
		}

		if string(peSignature) == "MZ\x90\x00" {
			peFile, err := os.Create(fmt.Sprintf("%08x.exe", offset))
			if err != nil {
				fmt.Printf("Error creating file: %v\n", err)
				break
			}
			defer peFile.Close()

			peData, err := peFile.ReadAt(offset, int(peFile.Size()-offset))
			if err != nil {
				fmt.Printf("Error reading PE data: %v\n", err)
				break
			}

			peFile.Write(peData)
		}
		offset++
	}
}
