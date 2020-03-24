package secbot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/360EntSecGroup-Skylar/excelize"
	"github.com/awnumar/memguard"
)

var baseURL = "https://www.googleapis.com"

// DriveFile represents each file in the v3 files payload
type DriveFile struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Name     string `"json:"name"`
	MimeType string `json:"mimeType"`
}

// DriveFilesPayload represents the files payload
type DriveFilesPayload struct {
	Kind             string      `json:"kind"`
	IncompleteSearch bool        `json:"incompleteSearch"`
	Files            []DriveFile `json:"files"`
}

// TokenRefreshPayload represents the token refresh payload
type TokenRefreshPayload struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
	GrantType    string `json:"grant_type"`
}

// TokenRefreshResponse represents the token refresh response
type TokenRefreshResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `"json:"scope"`
	TokenType   string `json:"token_type"`
}

// RefreshToken obtain a refresh token
func RefreshToken() (*string, error) {

	var responsePayload TokenRefreshResponse

	refreshToken, _ := memguard.NewImmutableFromBytes([]byte(os.Getenv("GDRIVE_REFRESH_TOKEN")))
	clientID, _ := memguard.NewImmutableFromBytes([]byte(os.Getenv("GDRIVE_CLIENT_ID")))
	clientSecret, _ := memguard.NewImmutableFromBytes([]byte(os.Getenv("GDRIVE_CLIENT_SECRET")))

	if refreshToken == nil || clientID == nil || clientSecret == nil {
		err := fmt.Errorf("error loading Google Drive credentials")
		return nil, err
	}

	content := TokenRefreshPayload{
		ClientID:     string(clientID.Buffer()),
		ClientSecret: string(clientSecret.Buffer()),
		RefreshToken: string(refreshToken.Buffer()),
		GrantType:    "refresh_token",
	}
	payload, _ := json.Marshal(content)

	req, _ := http.NewRequest("POST", baseURL+"/oauth2/v4/token", bytes.NewBuffer(payload))

	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	defer refreshToken.Destroy()
	defer clientID.Destroy()
	defer clientSecret.Destroy()

	if resp.StatusCode == http.StatusOK {

		body, err := ioutil.ReadAll(resp.Body)

		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(body, &responsePayload)

		if err != nil {
			return nil, err
		}

		return &responsePayload.AccessToken, nil
	}

	err = fmt.Errorf("error refreshing token! Status code: %d", resp.StatusCode)
	return nil, err
}

// GetFilesPayload obtains files list from API
func GetFilesPayload(token *string) (*DriveFilesPayload, error) {

	req, _ := http.NewRequest("GET", baseURL+"/drive/v3/files", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", "0")
	req.Header.Set("Authorization", "Bearer "+*token)

	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		payload := &DriveFilesPayload{}
		body, _ := ioutil.ReadAll(resp.Body)
		err = json.Unmarshal(body, &payload)

		if err != nil {
			return nil, err
		}
		return payload, nil
	}

	err = fmt.Errorf("error fetching files! Status code: %d", resp.StatusCode)
	return nil, err
}

// FindBaseFile obtains the ADP file by comparing name substring
func FindBaseFile(filesPayload *DriveFilesPayload) (*DriveFile, error) {

	for _, elem := range filesPayload.Files {
		if strings.Contains(elem.Name, "Base_ADP_BPs") {
			return &elem, nil
		}
	}

	err := errors.New("error finding the base file")
	return nil, err
}

// DownloadBaseFile downloads the xlsx file
func DownloadBaseFile(token *string, fileID string) (*string, error) {

	req, _ := http.NewRequest("GET", baseURL+"/drive/v3/files/"+fileID+"?alt=media", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", "0")
	req.Header.Set("Authorization", "Bearer "+*token)

	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusOK {
		fileName := "base_" + fileID + ".xlsx"

		out, err := os.Create(fileName)
		if err != nil {
			return nil, err
		}
		defer out.Close()
		defer resp.Body.Close()

		_, err = io.Copy(out, resp.Body)
		if err != nil {
			return nil, err
		}

		return &fileName, nil
	}

	err = fmt.Errorf("error fetching files! Status code: %d", resp.StatusCode)
	return nil, err

}

// ParseBaseFile parses the xlsx file
func ParseBaseFile(fileName string) (*map[string]string, error) {
	const Name = 1
	const Status = 4
	const Email = 12
	const CPF = 13
	var users = make(map[string]string)

	f, err := excelize.OpenFile(fileName)

	if err != nil {
		return nil, err
	}

	rows, err := f.Rows("Gera Arquivo")

	if err != nil {
		return nil, err
	}

	for rows.Next() {
		row, err := rows.Columns()

		if err != nil {
			return nil, err
		}

		if row[Status] == "INATIVO" {
			if row[Email] != "" {
				users[row[Email]] = row[CPF]
			}
		}
	}
	return &users, nil
}

// HandleGDriveFile handles the .xlsx file containing the users
func HandleGDriveFile() (*map[string]string, error) {

	token, err := RefreshToken()

	if err != nil {
		return nil, err
	}

	payload, err := GetFilesPayload(token)

	if err != nil {
		return nil, err
	}

	baseFile, err := FindBaseFile(payload)

	if err != nil {
		return nil, err
	}
	PostMessage(logs_channel, fmt.Sprintf("[GOOGLE DRIVE] Encontrou arquivo: %s", baseFile.Name))

	downloadedFile, err := DownloadBaseFile(token, baseFile.ID)

	if err != nil {
		return nil, err
	}
	PostMessage(logs_channel, fmt.Sprintf("[GOOGLE DRIVE] Processando arquivo: %s", *downloadedFile))

	users, err := ParseBaseFile(*downloadedFile)

	if err != nil {
		return nil, err
	}

	err = os.Remove(*downloadedFile)

	if err != nil {
		return nil, err
	}

	return users, nil
}

// FindGIMNotTerminated returns only not terminated emails
func FindGIMNotTerminated(emails *[]string) (*[]string, error) {

	var notTerminated []string
	alreadyTerminated, err := ListGIMTerminated()

	if err != nil {
		return nil, err
	}

	for _, email := range *emails {

		found := false
		for _, terminated := range *alreadyTerminated {
			if terminated == email {
				found = true
				break
			}
		}

		if found == false {
			notTerminated = append(notTerminated, email)
		}
	}

	return &notTerminated, nil
}
