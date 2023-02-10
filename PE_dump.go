package main

import (
	"fmt"
	"os"
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

	var offset int64
	offset = 0
	for {
		f.Seek(offset, 0)
		peSignature := make([]byte, 4)
		_, err = f.Read(peSignature)
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

			// Determine the size of the PE header
			peHeaderSize := int64(0)
			f.Seek(offset+0x3C, 0)
			f.Read(peSignature)
			peHeaderSize = int64(peSignature[0]) | int64(peSignature[1])<<8 | int64(peSignature[2])<<16 | int64(peSignature[3])<<24

			_, err = f.Seek(offset, 0)
			if err != nil {
				fmt.Printf("Error seeking in file: %v\n", err)
				break
			}

			peData := make([]byte, peHeaderSize)
			n, err := f.Read(peData)
			if err != nil || n == 0 {
				break
			}
			peFile.Write(peData[:n])
		}
		offset++
	}
}
