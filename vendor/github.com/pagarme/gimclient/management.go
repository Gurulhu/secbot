package gimclient

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type userComment struct {
	TotpSecret string `json:"totp_secret"`
	Status     string `json:"status"`
	CPF        string `json:"cpf"`
}

type userData struct {
	FullName string `json:"fullName"`
	Comment  string
}

type userRole struct {
	Role []string `json:"roles"`
}

// GenerateSecret generates the user's secret
func (c *Client) GenerateSecret() string {
	randbytes := make([]byte, 4)
	rand.Read(randbytes)
	totpsecret := hex.EncodeToString(randbytes)
	decodeddata := []byte(totpsecret)
	encodedtotp := base32.StdEncoding.EncodeToString(decodeddata)
	return encodedtotp
}

// DecodeSecret decode the user's secret
func (c *Client) DecodeSecret(encodeddata string) string {
	decodeddata, _ := base32.StdEncoding.DecodeString(encodeddata)
	return string(decodeddata)
}

// GetUser obtains the user
func (c *Client) GetUser(email string) (*http.Response, error) {
	path := fmt.Sprintf("/management/%v/users/%v", string(c.APPKey.Buffer()), strings.TrimSuffix(email, "\n"))
	return c.Get(path)
}

// AddUserToApp associates the user to the app
func (c *Client) AddUserToApp(email string, name string, secret string, cpf string) (*http.Response, error) {
	path := fmt.Sprintf("/management/%v/users/%v?includeRoles='readonly'", string(c.APPKey.Buffer()), strings.TrimSuffix(email, "\n"))
	comment, _ := json.Marshal(userComment{TotpSecret: secret, Status: "enabled", CPF: cpf})
	user := userData{FullName: name, Comment: string(comment)}
	data, _ := json.Marshal(user)

	return c.Put(path, bytes.NewBuffer(data))
}

// AddRoleToUser associates one or more roles to a user
func (c *Client) AddRoleToUser(email string, name string, role string) (*http.Response, error) {
	path := fmt.Sprintf("/management/%v/users/%v/roles", string(c.APPKey.Buffer()), strings.TrimSuffix(email, "\n"))

	// slice for future multi role sending
	roles := make([]string, 1)
	roles[0] = role
	data, _ := json.Marshal(userRole{Role: roles})

	return c.Post(path, bytes.NewBuffer(data))
}
