/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: adb_controller.go
Description: AndroidDeviceController using ADB and emulator automation. Implements
all DeviceController methods for device and emulator management, including app install/uninstall,
launch/stop, intent/event injection, screenshot, log collection, and device info. Robust error handling
and output parsing for reliable automation.
*/

package mobile

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// AndroidDeviceController implements DeviceController for Android devices/emulators via ADB
type AndroidDeviceController struct {
	DeviceID string // ADB device serial
	Emulator bool   // True if using emulator
}

func NewAndroidDeviceController(deviceID string, emulator bool) *AndroidDeviceController {
	return &AndroidDeviceController{DeviceID: deviceID, Emulator: emulator}
}

func (c *AndroidDeviceController) Start(ctx context.Context) error {
	// Check device connectivity
	cmd := exec.CommandContext(ctx, "adb", "-s", c.DeviceID, "wait-for-device")
	return cmd.Run()
}

func (c *AndroidDeviceController) Stop() error {
	// No-op for real device; for emulator, kill process
	if c.Emulator {
		cmd := exec.Command("adb", "-s", c.DeviceID, "emu", "kill")
		return cmd.Run()
	}
	return nil
}

func (c *AndroidDeviceController) InstallApp(appPath string) error {
	cmd := exec.Command("adb", "-s", c.DeviceID, "install", "-r", appPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("install failed: %v, output: %s", err, output)
	}
	if !bytes.Contains(output, []byte("Success")) {
		return fmt.Errorf("install failed: %s", output)
	}
	return nil
}

func (c *AndroidDeviceController) UninstallApp(packageName string) error {
	cmd := exec.Command("adb", "-s", c.DeviceID, "uninstall", packageName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("uninstall failed: %v, output: %s", err, output)
	}
	if !bytes.Contains(output, []byte("Success")) {
		return fmt.Errorf("uninstall failed: %s", output)
	}
	return nil
}

func (c *AndroidDeviceController) LaunchApp(packageName string) error {
	cmd := exec.Command("adb", "-s", c.DeviceID, "shell", "monkey", "-p", packageName, "-c", "android.intent.category.LAUNCHER", "1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("launch failed: %v, output: %s", err, output)
	}
	return nil
}

func (c *AndroidDeviceController) StopApp(packageName string) error {
	cmd := exec.Command("adb", "-s", c.DeviceID, "shell", "am", "force-stop", packageName)
	return cmd.Run()
}

func (c *AndroidDeviceController) SendIntent(intent *Intent) error {
	args := []string{"-s", c.DeviceID, "shell", "am", "start"}
	if intent.Action != "" {
		args = append(args, "-a", intent.Action)
	}
	if intent.Data != "" {
		args = append(args, "-d", intent.Data)
	}
	if intent.Package != "" {
		args = append(args, "-n", intent.Package)
	}
	for k, v := range intent.Extras {
		args = append(args, "--es", k, v)
	}
	cmd := exec.Command("adb", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("send intent failed: %v, output: %s", err, output)
	}
	return nil
}

func (c *AndroidDeviceController) SendEvent(event *UIEvent) error {
	// Only basic tap/input supported here; extend for swipe, etc.
	if event.Type == "tap" && event.Selector != "" {
		// Use input tap x y (Selector must be "x,y")
		coords := strings.Split(event.Selector, ",")
		if len(coords) == 2 {
			cmd := exec.Command("adb", "-s", c.DeviceID, "shell", "input", "tap", coords[0], coords[1])
			return cmd.Run()
		}
	}
	if event.Type == "input" && event.Selector != "" && event.Value != "" {
		// Use input text
		cmd := exec.Command("adb", "-s", c.DeviceID, "shell", "input", "text", event.Value)
		return cmd.Run()
	}
	// Extend for swipe, long-press, etc.
	return nil
}

func (c *AndroidDeviceController) TakeScreenshot(path string) error {
	tmp := "/sdcard/__akaylee_screenshot.png"
	cmd := exec.Command("adb", "-s", c.DeviceID, "shell", "screencap", "-p", tmp)
	if err := cmd.Run(); err != nil {
		return err
	}
	cmd = exec.Command("adb", "-s", c.DeviceID, "pull", tmp, path)
	if err := cmd.Run(); err != nil {
		return err
	}
	cmd = exec.Command("adb", "-s", c.DeviceID, "shell", "rm", tmp)
	_ = cmd.Run()
	return nil
}

func (c *AndroidDeviceController) GetLogs() ([]string, error) {
	cmd := exec.Command("adb", "-s", c.DeviceID, "logcat", "-d")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	var logs []string
	for scanner.Scan() {
		logs = append(logs, scanner.Text())
	}
	return logs, nil
}

func (c *AndroidDeviceController) GetDeviceInfo() (map[string]string, error) {
	info := make(map[string]string)
	cmd := exec.Command("adb", "-s", c.DeviceID, "shell", "getprop")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "[") {
			parts := strings.SplitN(line, ": ", 2)
			if len(parts) == 2 {
				key := strings.Trim(parts[0], "[]")
				val := strings.Trim(parts[1], "[]")
				info[key] = val
			}
		}
	}
	return info, nil
}
