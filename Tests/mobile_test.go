/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: mobile_test.go
Description: Comprehensive tests for the mobile fuzzing package. Tests AndroidDeviceController,
AndroidAppAnalyzer, AndroidIntentMutator, AndroidEventMutator, AndroidCrashReporter, and AndroidMobileFuzzer.
*/

package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/mobile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAndroidDeviceController tests the AndroidDeviceController
func TestAndroidDeviceController(t *testing.T) {
	runTest(t, "TestAndroidDeviceController", func(t *testing.T) {
		controller := mobile.NewAndroidDeviceController("test-device", false)
		require.NotNil(t, controller)

		// Test device controller interface compliance
		var deviceController mobile.DeviceController
		deviceController = controller
		assert.NotNil(t, deviceController)

		// Test starting device controller
		ctx := context.Background()
		err := controller.Start(ctx)
		if err != nil {
			t.Logf("Device controller start failed as expected: %v", err)
		}

		// Test app installation (will fail without real device)
		err = controller.InstallApp("test.apk")
		if err != nil {
			t.Logf("App installation failed as expected: %v", err)
		}

		// Test app uninstallation
		err = controller.UninstallApp("com.test.app")
		if err != nil {
			t.Logf("App uninstallation failed as expected: %v", err)
		}

		// Test app launch
		err = controller.LaunchApp("com.test.app")
		if err != nil {
			t.Logf("App launch failed as expected: %v", err)
		}

		// Test app stop
		err = controller.StopApp("com.test.app")
		if err != nil {
			t.Logf("App stop failed as expected: %v", err)
		}

		// Test intent sending
		intent := &mobile.Intent{
			Action:  "android.intent.action.VIEW",
			Data:    "https://example.com",
			Package: "com.test.app",
		}
		err = controller.SendIntent(intent)
		if err != nil {
			t.Logf("Intent sending failed as expected: %v", err)
		}

		// Test event sending
		event := &mobile.UIEvent{
			Type:      "tap",
			Selector:  "button#test",
			Value:     "",
			Timestamp: time.Now(),
		}
		err = controller.SendEvent(event)
		if err != nil {
			t.Logf("Event sending failed as expected: %v", err)
		}

		// Test screenshot capture
		err = controller.TakeScreenshot("test_screenshot.png")
		if err != nil {
			t.Logf("Screenshot capture failed as expected: %v", err)
		}

		// Test log collection
		logs, err := controller.GetLogs()
		if err != nil {
			t.Logf("Log collection failed as expected: %v", err)
		} else {
			assert.NotNil(t, logs)
		}

		// Test device info
		info, err := controller.GetDeviceInfo()
		if err != nil {
			t.Logf("Device info failed as expected: %v", err)
		} else {
			assert.NotNil(t, info)
		}

		// Test stopping device controller
		err = controller.Stop()
		if err != nil {
			t.Logf("Device controller stop failed: %v", err)
		}
	})
}

// TestAndroidAppAnalyzer tests the AndroidAppAnalyzer
func TestAndroidAppAnalyzer(t *testing.T) {
	runTest(t, "TestAndroidAppAnalyzer", func(t *testing.T) {
		analyzer := mobile.NewAndroidAppAnalyzer()
		require.NotNil(t, analyzer)

		// Test analyzer interface compliance
		var appAnalyzer mobile.AppAnalyzer
		appAnalyzer = analyzer
		assert.NotNil(t, appAnalyzer)

		// Test app analysis (will fail without real APK)
		analysis, err := analyzer.AnalyzeApp("test.apk")
		if err != nil {
			t.Logf("App analysis failed as expected: %v", err)
		} else {
			assert.NotNil(t, analysis)
		}

		// Test manifest analysis
		manifest, err := analyzer.AnalyzeManifest("AndroidManifest.xml")
		if err != nil {
			t.Logf("Manifest analysis failed as expected: %v", err)
		} else {
			assert.NotNil(t, manifest)
		}

		// Test running app analysis
		runtime, err := analyzer.AnalyzeRunningApp("com.test.app")
		if err != nil {
			t.Logf("Runtime analysis failed as expected: %v", err)
		} else {
			assert.NotNil(t, runtime)
		}

		// Test analyzer properties
		assert.NotEmpty(t, analyzer.Name())
		assert.NotEmpty(t, analyzer.Description())
	})
}

// TestAndroidIntentMutator tests the AndroidIntentMutator
func TestAndroidIntentMutator(t *testing.T) {
	runTest(t, "TestAndroidIntentMutator", func(t *testing.T) {
		mutator := mobile.NewAndroidIntentMutator()
		require.NotNil(t, mutator)

		// Test mutator interface compliance
		var intentMutator mobile.IntentMutator
		intentMutator = mutator
		assert.NotNil(t, intentMutator)

		// Test intent mutation
		originalIntent := &mobile.Intent{
			Action:  "android.intent.action.VIEW",
			Data:    "https://example.com",
			Extras:  map[string]string{"key": "value"},
			Package: "com.test.app",
		}

		mutated := mutator.MutateIntent(originalIntent)
		assert.NotNil(t, mutated)
		assert.NotEqual(t, originalIntent, mutated)

		// Test mutator properties
		assert.NotEmpty(t, mutator.Name())
		assert.NotEmpty(t, mutator.Description())
	})
}

// TestAndroidEventMutator tests the AndroidEventMutator
func TestAndroidEventMutator(t *testing.T) {
	runTest(t, "TestAndroidEventMutator", func(t *testing.T) {
		mutator := mobile.NewAndroidEventMutator()
		require.NotNil(t, mutator)

		// Test mutator interface compliance
		var eventMutator mobile.EventMutator
		eventMutator = mutator
		assert.NotNil(t, eventMutator)

		// Test event mutation
		originalEvent := &mobile.UIEvent{
			Type:      "tap",
			Selector:  "button#test",
			Value:     "",
			Timestamp: time.Now(),
		}

		mutated := mutator.MutateEvent(originalEvent)
		assert.NotNil(t, mutated)
		assert.NotEqual(t, originalEvent, mutated)

		// Test mutator properties
		assert.NotEmpty(t, mutator.Name())
		assert.NotEmpty(t, mutator.Description())
	})
}

// TestAndroidCrashReporter tests the AndroidCrashReporter
func TestAndroidCrashReporter(t *testing.T) {
	runTest(t, "TestAndroidCrashReporter", func(t *testing.T) {
		reporter := mobile.NewAndroidCrashReporter()
		require.NotNil(t, reporter)

		// Test reporter interface compliance
		var crashReporter mobile.CrashReporter
		crashReporter = reporter
		assert.NotNil(t, crashReporter)

		// Test crash collection (will fail without real device)
		crashes, err := reporter.CollectCrashes("com.test.app")
		if err != nil {
			t.Logf("Crash collection failed as expected: %v", err)
		} else {
			assert.NotNil(t, crashes)
		}

		// Test crash reporting
		crash := &mobile.CrashReport{
			PackageName: "com.test.app",
			Timestamp:   time.Now(),
			Type:        "crash",
			Message:     "Test crash",
			StackTrace:  "Test stack trace",
			Logs:        []string{"Test log"},
			DeviceInfo:  map[string]string{"device": "test"},
			Metadata:    map[string]interface{}{"key": "value"},
		}

		err = reporter.ReportCrash(crash)
		if err != nil {
			t.Logf("Crash reporting failed: %v", err)
		}

		// Test reporter properties
		assert.NotEmpty(t, reporter.Name())
		assert.NotEmpty(t, reporter.Description())
	})
}

// TestAndroidMobileFuzzer tests the AndroidMobileFuzzer
func TestAndroidMobileFuzzer(t *testing.T) {
	runTest(t, "TestAndroidMobileFuzzer", func(t *testing.T) {
		fuzzer := mobile.NewAndroidMobileFuzzer("test-device", "com.test.app")
		require.NotNil(t, fuzzer)

		// Test fuzzer interface compliance
		var mobileFuzzer mobile.MobileFuzzer
		mobileFuzzer = fuzzer
		assert.NotNil(t, mobileFuzzer)

		// Test fuzzer configuration
		deviceController := mobile.NewAndroidDeviceController("test-device", false)
		analyzer := mobile.NewAndroidAppAnalyzer()
		intentMutator := mobile.NewAndroidIntentMutator()
		eventMutator := mobile.NewAndroidEventMutator()
		crashReporter := mobile.NewAndroidCrashReporter()

		err := fuzzer.Configure(deviceController, analyzer, intentMutator, eventMutator, crashReporter)
		require.NoError(t, err)

		// Test fuzzer start (will fail without real device)
		ctx := context.Background()
		err = fuzzer.Start(ctx)
		if err != nil {
			t.Logf("Fuzzer start failed as expected: %v", err)
		}

		// Test fuzzer status
		status := fuzzer.Status()
		assert.NotEmpty(t, status)

		// Test fuzzer stop
		err = fuzzer.Stop()
		if err != nil {
			t.Logf("Fuzzer stop failed: %v", err)
		}
	})
}

// TestMobileIntegration tests integration between mobile components
func TestMobileIntegration(t *testing.T) {
	runTest(t, "TestMobileIntegration", func(t *testing.T) {
		// Test device controller with app analyzer
		controller := mobile.NewAndroidDeviceController("test-device", false)
		analyzer := mobile.NewAndroidAppAnalyzer()

		// Test intent mutator with event mutator
		intentMutator := mobile.NewAndroidIntentMutator()
		eventMutator := mobile.NewAndroidEventMutator()

		// Test crash reporter integration
		reporter := mobile.NewAndroidCrashReporter()

		// Test mobile fuzzer with all components
		fuzzer := mobile.NewAndroidMobileFuzzer("test-device", "com.test.app")
		require.NotNil(t, fuzzer)

		// Configure fuzzer with all components
		err := fuzzer.Configure(controller, analyzer, intentMutator, eventMutator, reporter)
		require.NoError(t, err)

		// All components should be properly initialized
		assert.NotNil(t, controller)
		assert.NotNil(t, analyzer)
		assert.NotNil(t, intentMutator)
		assert.NotNil(t, eventMutator)
		assert.NotNil(t, reporter)
		assert.NotNil(t, fuzzer)
	})
}

// TestMobileEdgeCases tests edge cases for mobile components
func TestMobileEdgeCases(t *testing.T) {
	runTest(t, "TestMobileEdgeCases", func(t *testing.T) {
		// Test with empty device ID
		controller := mobile.NewAndroidDeviceController("", false)
		assert.NotNil(t, controller)

		// Test with nil intents
		intentMutator := mobile.NewAndroidIntentMutator()
		mutated := intentMutator.MutateIntent(nil)
		assert.Nil(t, mutated)

		// Test with nil events
		eventMutator := mobile.NewAndroidEventMutator()
		mutatedEvent := eventMutator.MutateEvent(nil)
		assert.Nil(t, mutatedEvent)

		// Test with empty app path
		analyzer := mobile.NewAndroidAppAnalyzer()
		_, err := analyzer.AnalyzeApp("")
		assert.Error(t, err)

		// Test with empty package name
		reporter := mobile.NewAndroidCrashReporter()
		_, err = reporter.CollectCrashes("")
		assert.Error(t, err)

		// Test with nil crash report
		err = reporter.ReportCrash(nil)
		assert.Error(t, err)

		// Test fuzzer with nil components
		fuzzer := mobile.NewAndroidMobileFuzzer("test-device", "com.test.app")
		err = fuzzer.Configure(nil, nil, nil, nil, nil)
		assert.Error(t, err)
	})
}
