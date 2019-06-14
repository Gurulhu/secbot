package secbot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"

	"github.com/nlopes/slack"
)

// MetabaseUser represents the Metabase user payload
type MetabaseUser struct {
	User     string `json:"username"`
	Password string `json:"password"`
}

// MetabaseToken represents the Metabase token response
type MetabaseToken struct {
	ID string `json:"id"`
}

// MetabaseUserDetail represents the Metabase user detail
type MetabaseUserDetail struct {
	ID         int    `json:"id"`
	Email      string `json:"email"`
	FirstName  string `json:"first_name"`
	LastName   string `json:"last_name"`
	CommonName string `json:"common_name"`
}

// MetabaseUserList represents the Metabase user list
type MetabaseUserList []MetabaseUserDetail

// MetabaseHandlerStart handler for metabase
func MetabaseHandlerStart() {

	RegisterHandler("metabase")

	AddCommand(Command{
		Regex:              regexp.MustCompile("metabase (?P<command>set application) (?P<user>\\S+) (?P<password>\\S+)"),
		Help:               "Seta as credenciais do Metabase com os dados informados",
		Usage:              "metabase set application <user> <password>",
		Handler:            MetabaseSetApplicationCommand,
		RequiredPermission: "metabase",
		HandlerName:        "metabase",
		Parameters: map[string]string{
			"user":     "\\S+",
			"password": "\\S+",
		}})
}

// MetabaseGetCredentials obtain the stored metabase credentials
func MetabaseGetCredentials() (ExternalCredential, error) {

	cred, err := CredentialsGetCredential("metabase", "metabase")

	return cred, err
}

// MetabaseSetApplicationCommand inserrts credential
func MetabaseSetApplicationCommand(md map[string]string, ev *slack.MessageEvent) {

	DeleteMessage(ev)

	var ex ExternalCredential

	ex.Module = "metabase"
	ex.Name = "metabase"
	ex.Login = md["user"]
	ex.Password = md["password"]

	err := CredentialsSetCredential(ex)

	if err != nil {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Ocorreu um erro cadastrando a aplicação `%s`: %s",
			ev.Username, ex.Module, err.Error()))
	} else {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Aplicação `%s` cadastrada com sucesso",
			ev.Username, ex.Module))
	}

}

// ObtainMetabaseToken obtain a token for the user
func ObtainMetabaseToken() (*string, error) {

	var responsePayload MetabaseToken

	metabaseDomain := os.Getenv("METABASE_DOMAIN")

	if metabaseDomain == "" {
		err := fmt.Errorf("error loading Metabase user")
		return nil, err
	}

	if metabaseURL == "" {
		err := fmt.Errorf("error loading Metabase url")
		return nil, err
	}

	cred, err := MetabaseGetCredentials()

	if err != nil {
		return nil, err
	}

	content := MetabaseUser{User: cred.Login + "@" + metabaseDomain, Password: cred.Password}
	payload, _ := json.Marshal(content)
	req, _ := http.NewRequest("POST", metabaseURL+"/api/session", bytes.NewBuffer(payload))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)

		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(body, &responsePayload)

		if err != nil {
			return nil, err
		}

		return &responsePayload.ID, nil

	}

	err = fmt.Errorf("error fetching token! Status code: %d", resp.StatusCode)
	return nil, err
}

// ObtainMetabaseUsers obtains metabase users payload
func ObtainMetabaseUsers(token string) (*MetabaseUserList, error) {

	var responsePayload MetabaseUserList

	if metabaseURL == "" {
		err := fmt.Errorf("error loading Metabase url")
		return nil, err
	}

	req, _ := http.NewRequest("GET", metabaseURL+"/api/user", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Metabase-Session", token)

	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)

		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(body, &responsePayload)

		if err != nil {
			return nil, err
		}

		return &responsePayload, nil
	}

	err = fmt.Errorf("error fetching users! Status code: %d", resp.StatusCode)
	return nil, err

}

// FindMetabaseNotTerminated returns only not terminated emails
func FindMetabaseNotTerminated(emails *[]string) (*[]string, error) {

	var notTerminated []string
	alreadyTerminated, err := ListMetabaseTerminated()

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

// FindMetabaseNotTerminatedID find users id by email
func FindMetabaseNotTerminatedID(emails *[]string, metabaseUsers MetabaseUserList) (map[string]int, error) {

	usersMap := make(map[string]int)

	for _, email := range *emails {
		for _, user := range metabaseUsers {
			if email == user.Email {
				usersMap[email] = user.ID
				break
			}
		}
	}

	return usersMap, nil
}

// DeactivateMetabaseUser deactivates the user using its id
func DeactivateMetabaseUser(userID string, token string) (bool, error) {

	req, _ := http.NewRequest("DELETE", metabaseURL+"/api/user/"+userID, nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Metabase-Session", token)

	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true, nil
	}

	err = fmt.Errorf("error deactivating user! Status code: %d", resp.StatusCode)
	return false, err
}
