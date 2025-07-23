/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: Akaylee.go
Description: Dual-mode fuzzer for vulnscan. Supports both direct binary fuzzing (stdin, no port) and network fuzzing (HTTP POST to random port). For each test case, runs vulnscan in the appropriate mode, captures output, exit code, and errors. Writes detailed HTML/JSON reports to ./fuzz_output. Modular, clean, and beautiful.
*/

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type FuzzResult struct {
	TestCase string `json:"test_case"`
	Mode     string `json:"mode"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
	Output   string `json:"output,omitempty"`
	ExitCode int    `json:"exit_code,omitempty"`
	Signal   string `json:"signal,omitempty"`
	Duration string `json:"duration"`
}

func findFreePort() (int, error) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func runDirectFuzz(testInput []byte) (FuzzResult, error) {
	start := time.Now()
	cmd := exec.Command("TARGET/vulnscan", "--fuzz")
	cmd.Env = append(os.Environ(), "VULNSCAN_FUZZ=1")
	cmd.Stdin = bytes.NewReader(testInput)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	dur := time.Since(start)
	result := FuzzResult{
		Mode:     "direct",
		Status:   "ok",
		Output:   outBuf.String() + errBuf.String(),
		Duration: dur.String(),
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		result.ExitCode = exitErr.ExitCode()
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			result.Signal = ws.Signal().String()
		}
		result.Status = "crash"
		result.Error = err.Error()
	} else if err != nil {
		result.Status = "error"
		result.Error = err.Error()
	}
	return result, nil
}

func runNetworkFuzz(testInput []byte) (FuzzResult, error) {
	start := time.Now()
	port, err := findFreePort()
	if err != nil {
		return FuzzResult{Mode: "network", Status: "error", Error: err.Error()}, err
	}
	cmd := exec.Command("TARGET/vulnscan")
	cmd.Env = append(os.Environ(), fmt.Sprintf("VULNSCAN_PORT=%d", port))
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		return FuzzResult{Mode: "network", Status: "error", Error: err.Error()}, err
	}
	// Wait for server to start
	serverUp := false
	for i := 0; i < 20; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			conn.Close()
			serverUp = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !serverUp {
		cmd.Process.Kill()
		return FuzzResult{Mode: "network", Status: "error", Error: "server did not start"}, fmt.Errorf("server did not start")
	}
	// Send HTTP POST
	url := fmt.Sprintf("http://127.0.0.1:%d/report", port)
	resp, err := http.Post(url, "text/plain", bytes.NewReader(testInput))
	if err != nil {
		cmd.Process.Kill()
		return FuzzResult{Mode: "network", Status: "error", Error: err.Error()}, err
	}
	respBody, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	// Shutdown server
	cmd.Process.Kill()
	cmd.Wait()
	dur := time.Since(start)
	result := FuzzResult{
		Mode:     "network",
		Status:   "ok",
		Output:   string(respBody) + outBuf.String() + errBuf.String(),
		Duration: dur.String(),
	}
	if resp.StatusCode != 200 {
		result.Status = "crash"
		result.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return result, nil
}

func main() {
	var results []FuzzResult
	defer func() {
		if r := recover(); r != nil {
			timestamp := time.Now().Format("2006-01-02_15-04-05")
			jsonPath := filepath.Join("./fuzz_output", fmt.Sprintf("vulnscan_fuzz_report_panic_%s.json", timestamp))
			htmlPath := filepath.Join("./fuzz_output", fmt.Sprintf("vulnscan_fuzz_report_panic_%s.html", timestamp))
			jsonData, _ := json.MarshalIndent(results, "", "  ")
			os.WriteFile(jsonPath, jsonData, 0644)
			writeHTMLReport(htmlPath, results)
		}
	}()
	corpusDir := "TARGET/corpus/split"
	outputDir := "./fuzz_output"
	os.MkdirAll(outputDir, 0755)
	files, _ := filepath.Glob(filepath.Join(corpusDir, "*"))
	for _, file := range files {
		input, err := os.ReadFile(file)
		if err != nil {
			results = append(results, FuzzResult{TestCase: file, Status: "error", Error: err.Error()})
			continue
		}
		directRes, _ := runDirectFuzz(input)
		directRes.TestCase = file
		results = append(results, directRes)
		netRes, _ := runNetworkFuzz(input)
		netRes.TestCase = file
		results = append(results, netRes)
		timestamp := time.Now().Format("2006-01-02_15-04-05")
		jsonPath := filepath.Join(outputDir, fmt.Sprintf("vulnscan_fuzz_report_live_%s.json", timestamp))
		htmlPath := filepath.Join(outputDir, fmt.Sprintf("vulnscan_fuzz_report_live_%s.html", timestamp))
		jsonData, _ := json.MarshalIndent(results, "", "  ")
		os.WriteFile(jsonPath, jsonData, 0644)
		writeHTMLReport(htmlPath, results)
	}
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	jsonPath := filepath.Join(outputDir, fmt.Sprintf("vulnscan_fuzz_report_final_%s.json", timestamp))
	htmlPath := filepath.Join(outputDir, fmt.Sprintf("vulnscan_fuzz_report_final_%s.html", timestamp))
	jsonData, _ := json.MarshalIndent(results, "", "  ")
	os.WriteFile(jsonPath, jsonData, 0644)
	writeHTMLReport(htmlPath, results)
}

func writeHTMLReport(path string, results []FuzzResult) {
	f, err := os.Create(path)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString("<html><head><title>Akaylee Fuzz Report</title><style>body{font-family:sans-serif;}table{border-collapse:collapse;}th,td{border:1px solid #ccc;padding:4px;}th{background:#eee;}tr.crash{background:#fdd;}tr.ok{background:#dfd;}tr.error{background:#ffd;}tr.network{background:#ddf;}tr.direct{background:#fdf;}</style></head><body>")
	f.WriteString("<h1>Akaylee Fuzz Report</h1><table><tr><th>Test Case</th><th>Mode</th><th>Status</th><th>Error</th><th>Exit Code</th><th>Signal</th><th>Duration</th><th>Output</th></tr>")
	for _, r := range results {
		rowClass := r.Status
		f.WriteString(fmt.Sprintf("<tr class='%s'><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td><pre>%s</pre></td></tr>", rowClass, r.TestCase, r.Mode, r.Status, r.Error, r.ExitCode, r.Signal, r.Duration, htmlEscape(r.Output)))
	}
	f.WriteString("</table></body></html>")
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}
