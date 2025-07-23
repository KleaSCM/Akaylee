/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: mobile.go
Description: CLI command for mobile app fuzzing. Provides flags for device/app selection, install,
launch, fuzz, and stop. Wires up AndroidMobileFuzzer and all components for mobile fuzzing.
*/

package commands

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/mobile"
	"github.com/spf13/cobra"
)

var (
	mobileTarget   string
	mobileApp      string
	mobileDeviceID string
	mobileEmulator bool
	mobileInstall  bool
	mobileLaunch   bool
	mobileFuzz     bool
	mobileStop     bool
)

func init() {
	mobileCmd.Flags().StringVar(&mobileTarget, "mobile-target", "", "Mobile app package name (required)")
	mobileCmd.Flags().StringVar(&mobileApp, "mobile-app", "", "Path to APK/IPA file (required for install)")
	mobileCmd.Flags().StringVar(&mobileDeviceID, "mobile-device-id", "", "ADB device serial (default: first device)")
	mobileCmd.Flags().BoolVar(&mobileEmulator, "mobile-emulator", false, "Use emulator (default: false)")
	mobileCmd.Flags().BoolVar(&mobileInstall, "mobile-install", false, "Install app before fuzzing")
	mobileCmd.Flags().BoolVar(&mobileLaunch, "mobile-launch", false, "Launch app before fuzzing")
	mobileCmd.Flags().BoolVar(&mobileFuzz, "mobile-fuzz", false, "Start fuzzing loop")
	mobileCmd.Flags().BoolVar(&mobileStop, "mobile-stop", false, "Stop app and device after fuzzing")
	mobileCmd.MarkFlagRequired("mobile-target")
}

var mobileCmd = &cobra.Command{
	Use:   "mobile",
	Short: "Fuzz mobile apps (Android/iOS) with device/emulator automation",
	Long: `Fuzz mobile apps using real devices or emulators. Supports install, launch, intent/event mutation,
crash monitoring, and reporting. Production-level pipeline for Android (ADB, Monkey, UIAutomator).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Handle signals for graceful shutdown
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-c
			fmt.Println("\n[!] Interrupt received, stopping mobile fuzzer...")
			cancel()
		}()

		// Setup device controller
		device := mobile.NewAndroidDeviceController(mobileDeviceID, mobileEmulator)
		analyzer := mobile.NewAndroidAppAnalyzer()
		intentMutator := mobile.NewAndroidIntentMutator()
		eventMutator := mobile.NewAndroidEventMutator()
		crashReporter := mobile.NewAndroidCrashReporter()

		fuzzer := mobile.NewAndroidMobileFuzzer(mobileTarget, mobileApp)
		fuzzer.Configure(device, analyzer, intentMutator, eventMutator, crashReporter)

		if mobileInstall {
			fmt.Println("[*] Installing app...")
			if err := device.InstallApp(mobileApp); err != nil {
				return fmt.Errorf("install failed: %v", err)
			}
		}
		if mobileLaunch {
			fmt.Println("[*] Launching app...")
			if err := device.LaunchApp(mobileTarget); err != nil {
				return fmt.Errorf("launch failed: %v", err)
			}
		}
		if mobileFuzz {
			fmt.Println("[*] Starting mobile fuzzing loop...")
			if err := fuzzer.Start(ctx); err != nil {
				return fmt.Errorf("fuzzing failed: %v", err)
			}
			// Wait until cancelled
			for {
				select {
				case <-ctx.Done():
					fmt.Println("[*] Fuzzing stopped.")
					return nil
				default:
					fmt.Printf("[status] %s\n", fuzzer.Status())
					time.Sleep(5 * time.Second)
				}
			}
		}
		if mobileStop {
			fmt.Println("[*] Stopping app and device...")
			_ = device.StopApp(mobileTarget)
			_ = device.Stop()
		}
		return nil
	},
}

// Export MobileCmd for registration in main.go
var MobileCmd = mobileCmd
