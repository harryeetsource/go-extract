package main

import (
	"bytes"
	"debug/pe"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
)

const (
	maxMemory = 1 * 1024 * 1024 * 1024 // 1GB
	chunkSize = 1024 * 1024            // 1MB
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: go run extract.go <memory_dump_path> <output_dir>")
		os.Exit(1)
	}

	runtime.GOMAXPROCS(1) // Use only one processor to limit memory usage.

	// Open the memory dump file for reading.
	file, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// Create a buffer for reading the file contents into.
	buf := new(bytes.Buffer)

	// Read the memory dump file in chunks, limiting the memory usage to 1GB.
	var mem uint64
	for {
		chunk := make([]byte, chunkSize)
		n, err := file.Read(chunk)
		if err != nil {
			if err == io.EOF {
				break // End of file.
			}
			log.Fatal(err)
		}
		chunk = chunk[:n] // Trim to actual size.

		if mem+uint64(len(chunk)) > maxMemory {
			// Chunk would exceed the memory limit, skip it.
			continue
		}

		mem += uint64(len(chunk))
		_, err = buf.Write(chunk)
		if err != nil {
			log.Fatal(err)
		}

		if mem >= maxMemory {
			// Process the buffer when it reaches the memory limit.
			processBuffer(buf, os.Args[2])
			buf.Reset()
			mem = 0
		}
	}

	if buf.Len() > 0 {
		// Process the remaining buffer.
		processBuffer(buf, os.Args[2])
	}
}

func processBuffer(buf *bytes.Buffer, outputDir string) {
	// Find all portable executables in the memory dump.
	for len(buf.Bytes()) > 0 {
		// Parse the PE header.
		peFile, err := pe.NewFile(bytes.NewReader(buf.Bytes()))
		if err != nil {
			// Not a PE file, skip.
			buf.ReadByte()
			continue
		}

		// Check if the file is a 32-bit or 64-bit executable.
		if peFile.FileHeader.Machine != pe.IMAGE_FILE_MACHINE_AMD64 && peFile.FileHeader.Machine != pe.IMAGE_FILE_MACHINE_I386 {
			// Not a 32-bit or 64-bit executable, skip.
			buf.ReadByte()
			continue
		}

		// Check if the executable starts with the MZ header.
		if len(peFile.Sections) == 0 || buf.Len() < int(peFile.Sections[0].Offset)+2 {
			buf.ReadByte()
			continue
		}

		if buf.Bytes()[0] != 'M' || buf.Bytes()[1] != 'Z' {
			buf.ReadByte()
			continue
		}

		// Check if the executable has the "this program cannot be run in DOS mode" message.
		if len(buf.Bytes()) < int(peFile.Sections[0].Offset)+len("this program cannot be run in DOS mode") {
			buf.ReadByte()
			continue
		}
	
		if string(buf.Bytes()[int(peFile.Sections[0].Offset):int(peFile.Sections[0].Offset)+len("this program cannot be run in DOS mode")]) != "this program cannot be run in DOS mode" {
			buf.ReadByte()
			continue
		}
	
		// Calculate the size of the executable.
		var lastSection pe.Section
		for _, section := range peFile.Sections {
			if section.VirtualAddress > lastSection.VirtualAddress {
				lastSection = *section
			}
		}
		if len(peFile.Sections) == 0 {
			// No sections found, skip.
			buf.ReadByte()
			continue
		}
		size := int(lastSection.VirtualAddress) + int(lastSection.VirtualSize) - int(peFile.Sections[0].Offset)
	
		// Write the executable to a file in the output directory.
		outputFile, err := os.Create(filepath.Join(outputDir, fmt.Sprintf("output_%d.exe", len(peFile.Sections))))
		if err != nil {
			log.Fatal(err)
		}
	
		_, err = io.CopyN(outputFile, buf, int64(size))
		if err != nil {
			log.Fatal(err)
		}
		outputFile.Close()
	
		// Remove the processed bytes from the buffer.
		buf.Next(size)
	}
}	
