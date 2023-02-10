package main

import (
	"fmt"
	"os"
)

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
		f.Seek(offset, 0)
		peSignature := make([]byte, 4)
		_, err = f.Read(peSignature)
		if err != nil {
			break
		}

		if string(peSignature) == "PE\x00\x00" {
			peFile, err := os.Create(fmt.Sprintf("%08x.exe", offset))
			if err != nil {
				fmt.Printf("Error creating file: %v\n", err)
				break
			}
			defer peFile.Close()

			_, err = f.Seek(offset, 0)
			if err != nil {
				fmt.Printf("Error seeking in file: %v\n", err)
				break
			}

			peData := make([]byte, 65536)
			for {
				n, err := f.Read(peData)
				if err != nil || n == 0 {
					break
				}
				peFile.Write(peData[:n])
			}
		}
		offset++
	}
}
