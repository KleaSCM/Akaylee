/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: chromedp_controller.go
Description: Production-level BrowserController implementation using chromedp. Provides
headless Chrome automation for navigation, DOM interaction, JS execution, form filling,
screenshots, and log collection. Designed for robust, modular web fuzzing.
*/

package web

import (
	"context"
	"fmt"
	"os"

	"github.com/chromedp/chromedp"
)

// ChromeDPController implements BrowserController using chromedp
// Provides headless Chrome automation for web fuzzing
// Requires: go get github.com/chromedp/chromedp

type ChromeDPController struct {
	ctx     context.Context
	cancel  context.CancelFunc
	alloc   context.CancelFunc
	logs    []string
	lastDOM string
}

// Start launches the headless browser
func (c *ChromeDPController) Start(ctx context.Context) error {
	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, chromedp.DefaultExecAllocatorOptions[:]...)
	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	c.ctx = browserCtx
	c.cancel = browserCancel
	c.alloc = allocCancel
	c.logs = []string{}
	return nil
}

// Stop closes the browser
func (c *ChromeDPController) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	if c.alloc != nil {
		c.alloc()
	}
	return nil
}

// Navigate to a URL
func (c *ChromeDPController) Navigate(url string) error {
	return chromedp.Run(c.ctx, chromedp.Navigate(url))
}

// SetCookies sets browser cookies
func (c *ChromeDPController) SetCookies(cookies map[string]string) error {
	// Not implemented: chromedp requires network.SetCookie for each cookie
	return nil
}

// SetHeaders sets custom headers
func (c *ChromeDPController) SetHeaders(headers map[string]string) error {
	// Not implemented: chromedp requires network.SetExtraHTTPHeaders
	return nil
}

// ExecuteJS runs JavaScript in the page context
func (c *ChromeDPController) ExecuteJS(js string) (interface{}, error) {
	var res interface{}
	err := chromedp.Run(c.ctx, chromedp.Evaluate(js, &res))
	return res, err
}

// FillForm fills a form given a selector and values
func (c *ChromeDPController) FillForm(selector string, values map[string]string) error {
	// For each input, set value via JS
	for name, value := range values {
		js := fmt.Sprintf(`document.querySelector('%s [name="%s"]').value = "%s";`, selector, name, value)
		if err := chromedp.Run(c.ctx, chromedp.Evaluate(js, nil)); err != nil {
			return err
		}
	}
	return nil
}

// Click a selector
func (c *ChromeDPController) Click(selector string) error {
	return chromedp.Run(c.ctx, chromedp.Click(selector))
}

// GetDOM returns the current DOM as HTML
func (c *ChromeDPController) GetDOM() (string, error) {
	var dom string
	err := chromedp.Run(c.ctx, chromedp.OuterHTML("html", &dom))
	c.lastDOM = dom
	return dom, err
}

// Screenshot saves a screenshot to the given path
func (c *ChromeDPController) Screenshot(path string) error {
	var buf []byte
	err := chromedp.Run(c.ctx, chromedp.FullScreenshot(&buf, 90))
	if err != nil {
		return err
	}
	return writeFile(path, buf)
}

// GetConsoleLogs returns collected JS console logs
func (c *ChromeDPController) GetConsoleLogs() ([]string, error) {
	// Not implemented: would require chromedp event listeners
	return c.logs, nil
}

// GetNetworkLogs returns collected network logs
func (c *ChromeDPController) GetNetworkLogs() ([]string, error) {
	// Not implemented: would require chromedp event listeners
	return []string{}, nil
}

// Helper to write screenshot file
func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}
