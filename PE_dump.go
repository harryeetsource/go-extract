package main

import (
	"encoding/binary"
	"fmt"
	"os"
)

const MB = 1024 * 1024
const maxFileSize = 16 * 1024 * MB

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

	var offset int64
	offset = 0
	for {
		peSignature := make([]byte, 4)
		_, err = f.ReadAt(peSignature, offset)
		if err != nil {
			break
		}

		if string(peSignature) == "MZ\x90\x00" {
			var peSize uint32
			err = binary.Read(f, binary.LittleEndian, &peSize)
			if err != nil {
				fmt.Printf("Error reading PE size: %v\n", err)
				break
			}

			if int64(peSize) > maxFileSize {
				fmt.Printf("PE size is larger than %d MB, skipping\n", maxFileSize/MB)
				offset += int64(peSize)
				continue
			}

			outFile, err := os.Create(fmt.Sprintf("%08x.exe", offset))
			if err != nil {
				fmt.Printf("Error creating file: %v\n", err)
				break
			}
			defer outFile.Close()

			var peData []byte
			var bytesRead int
			var totalBytesRead int64
			for totalBytesRead < int64(peSize) {
				data := make([]byte, MB)
				bytesRead, err = f.ReadAt(data, totalBytesRead)
				if err != nil || bytesRead == 0 {
					break
				}
				totalBytesRead += int64(bytesRead)
				peData = append(peData, data[:bytesRead]...)
			}

			_, err = outFile.Write(peData)
			if err != nil {
				fmt.Printf("Error writing PE data: %v\n", err)
				break
			}

			offset += int64(peSize)
		} else {
			offset++
		}
	}
}
