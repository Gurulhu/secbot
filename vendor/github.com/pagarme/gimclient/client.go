package gimclient

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/awnumar/memguard"
)

const baseURL = "https://gim.stone.com.br/api"

// Client is the http client structure
type Client struct {
	httpClient *http.Client
	BaseURL    string
	APIKey     *memguard.LockedBuffer
	APPKey     *memguard.LockedBuffer
}

// addHeader adds headers to request
func addHeader(req *http.Request, apiKey *memguard.LockedBuffer) {
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("accept", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("bearer %v", string(apiKey.Buffer())))
}

// NewClient creates a new Client
func NewClient(apiKey, appKey *memguard.LockedBuffer) *Client {
	return &Client{
		httpClient: http.DefaultClient,
		BaseURL:    baseURL,
		APIKey:     apiKey,
		APPKey:     appKey,
	}
}

// Get executes the homonimous HTTP method
func (c *Client) Get(path string) (*http.Response, error) {
	endpoint := strings.TrimSuffix(c.BaseURL+path, "\n")
	req, err := http.NewRequest("GET", endpoint, nil)

	if err != nil {
		return nil, err
	}

	addHeader(req, c.APIKey)
	return c.httpClient.Do(req)
}

// Put executes the homonimous HTTP method
func (c *Client) Put(path string, data io.Reader) (*http.Response, error) {
	endpoint := strings.TrimSuffix(c.BaseURL+path, "\n")
	req, err := http.NewRequest("PUT", endpoint, data)

	if err != nil {
		return nil, err
	}

	addHeader(req, c.APIKey)
	resp, err := c.httpClient.Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	return resp, nil
}

// Post executes the homonimous HTTP method
func (c *Client) Post(path string, data io.Reader) (*http.Response, error) {
	endpoint := strings.TrimSuffix(c.BaseURL+path, "\n")
	req, err := http.NewRequest("POST", endpoint, data)

	if err != nil {
		return nil, err
	}

	addHeader(req, c.APIKey)
	resp, err := c.httpClient.Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	return resp, nil
}
