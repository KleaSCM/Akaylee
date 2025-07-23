/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: interfaces.go
Description: Core interfaces for mobile app fuzzing. Defines MobileFuzzer, DeviceController,
AppAnalyzer, IntentMutator, EventMutator, and CrashReporter for modular, production-level
Android/iOS fuzzing and automation.
*/

package mobile

import (
	"context"
	"time"
)

// DeviceType represents the type of mobile device/emulator
// e.g., Android, iOS, Emulator, RealDevice
type DeviceType string

const (
	DeviceAndroid  DeviceType = "android"
	DeviceIOS      DeviceType = "ios"
	DeviceEmulator DeviceType = "emulator"
	DeviceReal     DeviceType = "real"
)

// DeviceController abstracts device/emulator automation (ADB, UIAutomator, XCUITest, Frida)
type DeviceController interface {
	Start(ctx context.Context) error
	Stop() error
	InstallApp(appPath string) error
	UninstallApp(packageName string) error
	LaunchApp(packageName string) error
	StopApp(packageName string) error
	SendIntent(intent *Intent) error
	SendEvent(event *UIEvent) error
	TakeScreenshot(path string) error
	GetLogs() ([]string, error)
	GetDeviceInfo() (map[string]string, error)
}

// Intent represents an Android/iOS intent or deep link
type Intent struct {
	Action  string
	Data    string
	Extras  map[string]string
	Package string
}

// UIEvent represents a UI event (tap, swipe, input, etc.)
type UIEvent struct {
	Type      string // tap, swipe, input, etc.
	Selector  string // UI element selector
	Value     string // Input value (if any)
	Timestamp time.Time
}

// AppAnalyzer analyzes APK/IPA files and running apps for structure, permissions, and vulnerabilities
type AppAnalyzer interface {
	AnalyzeApp(appPath string) (*AppAnalysis, error)
	AnalyzeManifest(manifestPath string) (*ManifestAnalysis, error)
	AnalyzeRunningApp(packageName string) (*AppRuntimeAnalysis, error)
	Name() string
	Description() string
}

type AppAnalysis struct {
	PackageName  string
	Permissions  []string
	Activities   []string
	Services     []string
	Receivers    []string
	Providers    []string
	DeepLinks    []string
	ManifestPath string
	Version      string
	Metadata     map[string]interface{}
}

type ManifestAnalysis struct {
	PackageName string
	Permissions []string
	Activities  []string
	DeepLinks   []string
	Metadata    map[string]interface{}
}

type AppRuntimeAnalysis struct {
	PackageName string
	Processes   []string
	Threads     []string
	MemoryUsage uint64
	CPUUsage    float64
	Logs        []string
	Metadata    map[string]interface{}
}

// IntentMutator generates and mutates intents for fuzzing
type IntentMutator interface {
	MutateIntent(intent *Intent) *Intent
	Name() string
	Description() string
}

// EventMutator generates and mutates UI events for fuzzing
type EventMutator interface {
	MutateEvent(event *UIEvent) *UIEvent
	Name() string
	Description() string
}

// CrashReporter collects and reports crashes, ANRs, and security issues
type CrashReporter interface {
	CollectCrashes(packageName string) ([]*CrashReport, error)
	ReportCrash(crash *CrashReport) error
	Name() string
	Description() string
}

type CrashReport struct {
	PackageName string
	Timestamp   time.Time
	Type        string // crash, ANR, security
	Message     string
	StackTrace  string
	Logs        []string
	DeviceInfo  map[string]string
	Metadata    map[string]interface{}
}

// MobileFuzzer orchestrates the mobile fuzzing process
type MobileFuzzer interface {
	Configure(device DeviceController, analyzer AppAnalyzer, intentMutator IntentMutator, eventMutator EventMutator, crashReporter CrashReporter) error
	Start(ctx context.Context) error
	Stop() error
	Status() string
}
