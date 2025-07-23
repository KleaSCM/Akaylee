/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: fuzzer.go
Description: AndroidMobileFuzzer. Implements MobileFuzzer interface to orchestrate
Android device/emulator fuzzing: app install, launch, intent/event mutation, crash monitoring, and reporting.
Provides robust, modular, and extensible mobile fuzzing pipeline.
*/

package mobile

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"
)

// AndroidMobileFuzzer implements MobileFuzzer for Android
type AndroidMobileFuzzer struct {
	device        DeviceController
	analyzer      AppAnalyzer
	intentMutator IntentMutator
	eventMutator  EventMutator
	crashReporter CrashReporter

	packageName string
	appPath     string
	fuzzing     int32 // atomic
	status      string
}

func NewAndroidMobileFuzzer(packageName, appPath string) *AndroidMobileFuzzer {
	return &AndroidMobileFuzzer{
		packageName: packageName,
		appPath:     appPath,
		status:      "initialized",
	}
}

func (f *AndroidMobileFuzzer) Configure(device DeviceController, analyzer AppAnalyzer, intentMutator IntentMutator, eventMutator EventMutator, crashReporter CrashReporter) error {
	f.device = device
	f.analyzer = analyzer
	f.intentMutator = intentMutator
	f.eventMutator = eventMutator
	f.crashReporter = crashReporter
	f.status = "configured"
	return nil
}

func (f *AndroidMobileFuzzer) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&f.fuzzing, 0, 1) {
		return fmt.Errorf("fuzzer already running")
	}
	f.status = "starting"
	// Start device
	if err := f.device.Start(ctx); err != nil {
		f.status = "device start failed"
		return err
	}
	// Install app
	if err := f.device.InstallApp(f.appPath); err != nil {
		f.status = "install failed"
		return err
	}
	// Launch app
	if err := f.device.LaunchApp(f.packageName); err != nil {
		f.status = "launch failed"
		return err
	}
	f.status = "fuzzing"
	// Fuzzing loop
	go f.fuzzLoop(ctx)
	return nil
}

func (f *AndroidMobileFuzzer) fuzzLoop(ctx context.Context) {
	defer atomic.StoreInt32(&f.fuzzing, 0)
	for atomic.LoadInt32(&f.fuzzing) == 1 {
		select {
		case <-ctx.Done():
			f.status = "stopped"
			return
		default:
			// Mutate/generate intent
			intent := &Intent{Action: "android.intent.action.VIEW", Package: f.packageName}
			mutatedIntent := f.intentMutator.MutateIntent(intent)
			_ = f.device.SendIntent(mutatedIntent)
			// Mutate/generate event
			event := &UIEvent{Type: "tap", Selector: "100,200", Timestamp: time.Now()}
			mutatedEvent := f.eventMutator.MutateEvent(event)
			_ = f.device.SendEvent(mutatedEvent)
			// Monitor for crashes
			crashes, err := f.crashReporter.CollectCrashes(f.packageName)
			if err == nil && len(crashes) > 0 {
				for _, crash := range crashes {
					_ = f.crashReporter.ReportCrash(crash)
				}
			}
			// Sleep between iterations
			time.Sleep(2 * time.Second)
		}
	}
}

func (f *AndroidMobileFuzzer) Stop() error {
	if !atomic.CompareAndSwapInt32(&f.fuzzing, 1, 0) {
		return fmt.Errorf("fuzzer not running")
	}
	f.status = "stopping"
	_ = f.device.StopApp(f.packageName)
	_ = f.device.Stop()
	f.status = "stopped"
	return nil
}

func (f *AndroidMobileFuzzer) Status() string {
	return f.status
}
