/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: chromedp_controller.go
Description: BrowserController using chromedp. Implements real cookie/header management,
console log and network event collection, and session/state helpers for robust web fuzzing.
*/

package web

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
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
	netlogs []string
	lastDOM string
	headers map[string]string
	cookies map[string]string
	logMu   sync.Mutex
	netMu   sync.Mutex
}

// Start launches the headless browser and attaches event listeners
func (c *ChromeDPController) Start(ctx context.Context) error {
	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, chromedp.DefaultExecAllocatorOptions[:]...)
	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	c.ctx = browserCtx
	c.cancel = browserCancel
	c.alloc = allocCancel
	c.logs = []string{}
	c.netlogs = []string{}
	c.headers = make(map[string]string)
	c.cookies = make(map[string]string)

	// Attach event listeners for console, JS errors, and network
	chromedp.ListenTarget(c.ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventRequestWillBeSent:
			c.netMu.Lock()
			c.netlogs = append(c.netlogs, fmt.Sprintf("[REQ] %s %s", e.Request.Method, e.Request.URL))
			c.netMu.Unlock()
		case *network.EventResponseReceived:
			c.netMu.Lock()
			c.netlogs = append(c.netlogs, fmt.Sprintf("[RES] %d %s", e.Response.Status, e.Response.URL))
			c.netMu.Unlock()
		case *network.EventLoadingFailed:
			c.netMu.Lock()
			c.netlogs = append(c.netlogs, fmt.Sprintf("[ERR] %s %s", e.ErrorText, e.RequestID.String()))
			c.netMu.Unlock()
		case *runtime.EventConsoleAPICalled:
			c.logMu.Lock()
			for _, arg := range e.Args {
				c.logs = append(c.logs, fmt.Sprintf("[console] %s", arg.Value))
			}
			c.logMu.Unlock()
		case *runtime.EventExceptionThrown:
			c.logMu.Lock()
			c.logs = append(c.logs, fmt.Sprintf("[exception] %s", e.ExceptionDetails.Error()))
			c.logMu.Unlock()
		}
	})

	// Enable network and runtime events
	if err := chromedp.Run(c.ctx, network.Enable(), runtime.Enable()); err != nil {
		return err
	}

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

// SetCookies sets browser cookies using network.SetCookie
func (c *ChromeDPController) SetCookies(cookies map[string]string) error {
	for name, value := range cookies {
		action := network.SetCookie(name, value).WithDomain("").WithPath("/")
		if err := chromedp.Run(c.ctx, action); err != nil {
			return err
		}
		c.cookies[name] = value
	}
	return nil
}

// SetHeaders sets custom headers for all requests using network.SetExtraHTTPHeaders
func (c *ChromeDPController) SetHeaders(headers map[string]string) error {
	if len(headers) == 0 {
		return nil
	}
	hdrs := make(network.Headers)
	for k, v := range headers {
		hdrs[k] = v
		c.headers[k] = v
	}
	return chromedp.Run(c.ctx, network.SetExtraHTTPHeaders(hdrs))
}

// ExecuteJS runs JavaScript in the page context
func (c *ChromeDPController) ExecuteJS(js string) (interface{}, error) {
	var res interface{}
	err := chromedp.Run(c.ctx, chromedp.Evaluate(js, &res))
	return res, err
}

// FillForm fills a form given a selector and values
func (c *ChromeDPController) FillForm(selector string, values map[string]string) error {
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
	c.logMu.Lock()
	defer c.logMu.Unlock()
	logs := make([]string, len(c.logs))
	copy(logs, c.logs)
	return logs, nil
}

// GetNetworkLogs returns collected network logs
func (c *ChromeDPController) GetNetworkLogs() ([]string, error) {
	c.netMu.Lock()
	defer c.netMu.Unlock()
	netlogs := make([]string, len(c.netlogs))
	copy(netlogs, c.netlogs)
	return netlogs, nil
}

// ClearCookies clears all browser cookies
func (c *ChromeDPController) ClearCookies() error {
	return chromedp.Run(c.ctx, network.ClearBrowserCookies())
}

// ClearCache clears browser cache
func (c *ChromeDPController) ClearCache() error {
	return chromedp.Run(c.ctx, network.ClearBrowserCache())
}

// Helper to write screenshot file
func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}
