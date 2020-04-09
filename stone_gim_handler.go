package secbot

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/awnumar/memguard"
	"github.com/nlopes/slack"
	"github.com/pagarme/gimclient"
	sendgrid "github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

// GIMDeactivatePatch represents a patch to deactivate users
type GIMDeactivatePatch struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value bool   `json:"value"`
}

// GIMDeactivatePayload represents the patch payload to deactivate users
type GIMDeactivatePayload struct {
	DeactivatePatches []GIMDeactivatePatch `json:"patches"`
}

// GIMUser represents user struct
type GIMUser struct {
	UserKey                    string `json:"userKey"`
	Email                      string `json:"email"`
	Name                       string `json:"name"`
	Active                     bool   `json:"active"`
	LockedOut                  bool   `json:"lockedOut"`
	Comment                    string `json:"comment"`
	CreateDate                 string `json:"createDate"`
	FailedPasswordAttemptCount int    `json:"faliedPasswordAttemptCount"`
	AssociationDate            string `json:"associationDate"`
}

// GIMUsersPayload represents users payload
type GIMUsersPayload struct {
	Users                 []GIMUser `json:"users"`
	FirstPage             int       `json:"FirstPage"`
	NextPage              int       `json:"NextPage"`
	PreviousPage          int       `json:"PreviousPage"`
	LastPage              int       `json:"LastPage"`
	TotalRows             int       `json:"TotalRows"`
	Success               bool      `json:"Success"`
	OperationReport       []int     `json:"OperationReport"`
	RequestKey            string    `json:"RequestKey"`
	InternalExecutionTime int       `json:"InternalExecutionTime"`
	ExternalExecutionTime int       `json:"ExternalExecutionTime"`
	TotalExecutionTime    int       `json:"TotalExecutionTime"`
}

// UserTuple represents relevant user attribute to deactivation
type UserTuple struct {
	Email   string
	Comment string
}

func StoneGIMHandlerStart() {

	RegisterHandler("gim")

	AddCommand(Command{
		Regex:       regexp.MustCompile("gim (?P<command>list applications)"),
		Help:        "Lista as aplicações disponíveis",
		Usage:       "gim list applications",
		Handler:     GIMListApplicationsCommand,
		HandlerName: "gim"})

	AddCommand(Command{
		Regex:              regexp.MustCompile("gim (?P<application>\\S+) (?P<command>recover) (?P<users>.*)"),
		Help:               "Envia email de recuperação de senha para <users> da aplicação <application>",
		Usage:              "gim <application> recover <users>",
		Handler:            GIMRecoverCommand,
		RequiredPermission: "gim",
		HandlerName:        "gim",
		Parameters: map[string]string{
			"application": "\\S+",
			"users":       ".*",
		}})

	AddCommand(Command{
		Regex:              regexp.MustCompile("gim (?P<command>recover) (?P<users>.*)"),
		Help:               "Envia email de recuperação de senha para <users> da aplicação <application>",
		Usage:              "gim recover <users>",
		Handler:            GIMRecoverCommand,
		RequiredPermission: "gim",
		HandlerName:        "gim",
		Parameters: map[string]string{
			"users": ".*",
		}})

	AddCommand(Command{
		Regex:              regexp.MustCompile("gim (?P<command>delete) (?P<users>.*)"),
		Help:               "Desativa os <users> na aplicação <application>",
		Usage:              "gim delete <users>",
		Handler:            gimDeleteCommand,
		RequiredPermission: "gim",
		HandlerName:        "gim",
		Parameters: map[string]string{
			"users": ".*",
		}})

	AddCommand(Command{
		Regex:              regexp.MustCompile("gim (?P<command>invite) (?P<role>\\S+) (?P<users>\\S+) (?P<cpf>\\S+) (?P<name>.*)"),
		Help:               "Cadastra o <users> na aplicação <application>\n Roles: standard, readonly, financial_admin, admin",
		Usage:              "gim invite <role> <users> <cpf> <name>",
		Handler:            gimInviteCommand,
		RequiredPermission: "gim",
		HandlerName:        "gim",
		Parameters: map[string]string{
			"role":  "\\S+",
			"users": "\\S+",
			"cpf":   "\\S+",
			"name":  ".*",
		}})

	AddCommand(Command{
		Regex:              regexp.MustCompile("gim (?P<command>set default application) (?P<application>\\S+)"),
		Help:               "Define a aplicação padrão do GIM",
		Usage:              "gim set default application <application>",
		Handler:            GIMSetDefaultApplicationCommand,
		RequiredPermission: "gim",
		HandlerName:        "gim",
		Parameters: map[string]string{
			"application": "\\S+",
		}})

	AddCommand(Command{
		Regex:              regexp.MustCompile("gim (?P<command>set application) (?P<application>\\S+) (?P<key>\\S+) (?P<api_key>\\S+)"),
		Help:               "Seta a aplicação <application> com os dados informados",
		Usage:              "gim set application <application> <key> <api_key>",
		Handler:            GIMSetApplicationCommand,
		RequiredPermission: "gim",
		HandlerName:        "gim",
		Parameters: map[string]string{
			"application": "\\S+",
			"key":         "\\S+",
			"api_key":     "\\S+",
		}})

	AddCommand(Command{
		Regex:              regexp.MustCompile("gim (?P<command>deletecpf) (?P<cpf>.*)"),
		Help:               "Desativa os <cpf> na aplicação <application>",
		Usage:              "gim delete <cpf>",
		Handler:            gimDeleteCPFCommand,
		RequiredPermission: "gim",
		HandlerName:        "gim",
		Parameters: map[string]string{
			"cpf": ".*",
		}})
}

func GIMHasApplication(application string) bool {
	creds, err := GIMListApplications()

	if err != nil {
		return false
	}

	if creds == nil {
		return false
	} else {
		if stringInSlice(application, creds) {
			return true
		}
	}

	return false
}

/*
Sets the GIM default application.

HandlerName

 gim

RequiredPermission

 gim

Regex

 gim (?P<command>set default application) (?P<application>\\S+)

Usage

 gim set default application <application>
*/
func GIMSetDefaultApplicationCommand(md map[string]string, ev *slack.MessageEvent) {
	creds, _ := GIMListApplications()

	if !GIMHasApplication(md["application"]) {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Aplicação `%s` inválida, os valores possíveis são:\n%s",
			ev.Username, md["application"], strings.Join(creds, "\n")))
		return
	}

	SetHandlerConfig("gim", "default_application", md["application"])
	PostMessage(ev.Channel, fmt.Sprintf("@%s Aplicação padrão setada para `%s`",
		ev.Username, md["application"]))
}

func GIMValidateApplication(md map[string]string) (bool, string) {
	var application = ""

	if val, ok := md["application"]; ok {
		application = val
	} else {
		application, _ = GetHandlerConfig("gim", "default_application")
	}

	if len(application) == 0 {
		return false, application
	}

	return true, application
}

/*
Recovers an user password for the application.

HandlerName

 gim

RequiredPermission

 gim

Regex

 gim (?P<application>\\S+) (?P<command>recover) (?P<users>.*)

 gim (?P<command>recover) (?P<users>.*)

Usage

 gim <application> recover <users>

 gim recover <users>
*/
func GIMRecoverCommand(md map[string]string, ev *slack.MessageEvent) {

	avalid, application := GIMValidateApplication(md)

	if !avalid {
		PostMessage(ev.Channel, fmt.Sprintf("@%s nenhuma aplicação especificada e aplicação padrão não configurada\n"+
			"Utilize `gim set default application <application>` "+
			"ou invoque novamente o comando especificando a conta", ev.Username))
		return
	}

	cred, err := GIMGetCredentials(application)

	if err == sql.ErrNoRows {
		creds, err := GIMListApplications()

		if err != nil {
			PostMessage(ev.Channel, fmt.Sprintf("@%s Aplicação `%s` não encontrada", ev.Username, application))
		} else {
			PostMessage(ev.Channel, fmt.Sprintf("@%s Aplicação `%s` não encontrada, os valores possíveis sao:\n%s",
				ev.Username, application, strings.Join(creds, "\n")))
		}
		return
	}

	if err != nil {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Ocorreu um erro obtendo as credenciais da aplicação `%s`: %s", ev.Username, application, err.Error()))
		return
	}
	var users []string

	for _, v := range strings.Split(md["users"], " ") {
		users = append(users, StripMailTo(v))
	}

	PostMessage(ev.Channel, fmt.Sprintf("@%s Recuperando senha dos seguintes usuários: %s", ev.Username, strings.Join(users, " ")))

	var recovered []string

	var failed []GenericError

	for _, user := range users {
		client := &http.Client{}
		req, err := http.NewRequest("GET", fmt.Sprintf("https://gim.stone.com.br/api/management/%s/users/%s/password", cred.Login, user), nil)

		if err != nil {
			failed = append(failed, GenericError{Key: user,
				Error: fmt.Sprintf("Ocorreu um erro resetando a senha do usuário: %s",
					err.Error())})
			continue
		}

		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", cred.Password))
		resp, err := client.Do(req)

		if resp.StatusCode == 401 {
			failed = append(failed, GenericError{Key: user, Error: fmt.Sprintf("Permissão negada")})
			continue
		}

		var response map[string]interface{}

		decoder := json.NewDecoder(resp.Body)

		err = decoder.Decode(&response)

		if err != nil {
			failed = append(failed, GenericError{Key: user, Error: fmt.Sprintf("Ocorreu um erro decodificando"+
				" a resposta do GIM: %s", err.Error())})
			continue
		}

		if response["Success"].(bool) {
			recovered = append(recovered, user)
			continue
		} else {
			var report []interface{}
			report = response["OperationReport"].([]interface{})
			for _, r := range report {
				rep := r.(map[string]interface{})
				if rep["Message"] == "The specified user is not associated to this application." {
					failed = append(failed, GenericError{Key: user, Error: fmt.Sprintf("Usuário não encontrado na aplicação %s",
						application)})
					continue
				} else if rep["Message"] == "User not found." {
					failed = append(failed, GenericError{Key: user, Error: fmt.Sprintf("Usuário não encontrado")})
					continue
				} else {
					failed = append(failed, GenericError{Key: user, Error: fmt.Sprintf("Erro resetando a senha: %s",
						rep["Message"])})
					continue
				}
			}
		}

	}

	var msg = fmt.Sprintf("@%s *### Resultado ###*\n", ev.Username)

	if len(recovered) > 0 {
		msg += fmt.Sprintf("*Usuários Recuperados*\n%s", strings.Join(recovered, " "))
	}
	if len(failed) > 0 {
		msg += fmt.Sprintf("*Erros*\n")
		for _, v := range failed {
			msg += fmt.Sprintf("%s - `%s`\n", v.Key, v.Error)
		}
	}

	PostMessage(ev.Channel, msg)
}

func GIMGetCredentials(application string) (ExternalCredential, error) {
	cred, err := CredentialsGetCredential("gim", application)
	return cred, err
}

func GIMGetApplicationsWithDefault() []string {
	applications, _ := GIMListApplications()

	var napplications []string

	var def = GIMGetDefaultApplication()
	for _, v := range applications {
		if v == def {
			napplications = append(napplications, fmt.Sprintf("*%s* [default]", v))
		} else {
			napplications = append(napplications, v)
		}
	}

	return napplications
}

/*
Lists stored GIM applications.

HandlerName
 gim

Regex

 gim (?P<command>list applications)

Usage

 gim list applications
*/
func GIMListApplicationsCommand(md map[string]string, ev *slack.MessageEvent) {
	ncreds := GIMGetApplicationsWithDefault()

	if ncreds == nil {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Nenhuma aplicação cadastrada",
			ev.Username))
	} else {
		PostMessage(ev.Channel, fmt.Sprintf("@%s *### Lista de aplicações cadastradas ###*\n%s",
			ev.Username, strings.Join(ncreds, "\n")))
	}
}

func GIMListApplications() ([]string, error) {
	creds, err := CredentialsListCredentials("gim")

	if err != nil {
		return nil, err
	}

	if len(creds) > 0 {
		var applications []string

		for _, v := range creds {
			applications = append(applications, v.Name)

		}

		return applications, nil
	} else {
		return nil, nil
	}

}

func GIMGetDefaultApplication() string {

	application, _ := GetHandlerConfig("gim", "default_application")

	if len(application) == 0 {
		return ""
	}

	return application

}

/*
Creates a GIM application.

HandlerName

 gim

RequiredPermission

 gim

Regex

 gim (?P<command>set application) (?P<application>\\S+) (?P<key>\\S+) (?P<api_key>\\S+)

Usage

 gim set application <application> <key> <api_key>
*/
func GIMSetApplicationCommand(md map[string]string, ev *slack.MessageEvent) {

	DeleteMessage(ev)

	var ex ExternalCredential

	ex.Module = "gim"
	ex.Name = md["application"]
	ex.Login = md["key"]
	ex.Password = md["api_key"]

	err := CredentialsSetCredential(ex)

	if err != nil {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Ocorreu um erro cadastrando a aplicação `%s`: %s",
			ev.Username, md["application"], err.Error()))
	} else {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Aplicação `%s` cadastrada com sucesso",
			ev.Username, md["application"]))
	}

}

func gimDeleteCommand(md map[string]string, ev *slack.MessageEvent) {

	avalid, application := GIMValidateApplication(md)

	if !avalid {
		PostMessage(ev.Channel, fmt.Sprintf("@%s nenhuma aplicação especificada e aplicação padrão não configurada\n"+
			"Utilize `gim set default application <application>` "+
			"ou invoque novamente o comando especificando a conta", ev.Username))
		return
	}

	var users []string

	for _, v := range strings.Split(md["users"], " ") {
		users = append(users, StripMailTo(v))
	}

	PostMessage(ev.Channel, fmt.Sprintf("@%s Desativando os seguintes usuários: %s", ev.Username, strings.Join(users, " ")))

	var desactive []string

	var failed []GenericError

	for _, user := range users {
		status, statuscode, _ := GIMDeactivateUser(user)

		if !status {
			if statuscode == 890 {
				failed = append(failed, GenericError{Key: user,
					Error: fmt.Sprintf("Usuário não existe na aplicação %s",
						application)})
				continue
			} else {
				failed = append(failed, GenericError{Key: user,
					Error: fmt.Sprintf("Ocorreu um erro ao desativar o usuário: status code: %s",
						statuscode)})
				continue
			}
		}

		desactive = append(desactive, user)
	}

	var msg = fmt.Sprintf("@%s *### Resultado ###*\n", ev.Username)

	if len(desactive) > 0 {
		msg += fmt.Sprintf("*Usuários Desativados*\n%s\n", strings.Join(desactive, " "))
	}
	if len(failed) > 0 {
		msg += fmt.Sprintf("*Erros*\n")
		for _, v := range failed {
			msg += fmt.Sprintf("%s - `%s`\n", v.Key, v.Error)
		}
	}

	PostMessage(ev.Channel, msg)
}

// GIMDeactivateUser deactivate an user
func GIMDeactivateUser(user string) (bool, int, error) {

	cred, err := GIMGetCredentials(string(credentialApp.Buffer()))

	apiKey, _ := memguard.NewImmutableFromBytes([]byte(cred.Password))
	appKey, _ := memguard.NewImmutableFromBytes([]byte(cred.Login))

	gclient := gimclient.NewClient(apiKey, appKey)

	gresp, err := gclient.GetUser(user)
	apiKey.Destroy()
	appKey.Destroy()
	if err != nil {
		return false, gresp.StatusCode, err
	} else if gresp.StatusCode == 400 {
		return false, 890, err
	}

	content := []GIMDeactivatePatch{{Op: "replace", Path: "/active", Value: false}}
	payload, _ := json.Marshal(GIMDeactivatePayload{DeactivatePatches: content})

	client := &http.Client{}
	req, err := http.NewRequest("PATCH", fmt.Sprintf("https://gim.stone.com.br/api/management/%s/users/%s", cred.Login, user), bytes.NewBuffer(payload))

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", cred.Password))

	resp, err := client.Do(req)

	if err != nil {
		return false, resp.StatusCode, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true, resp.StatusCode, nil
	} else {
		return false, resp.StatusCode, nil
	}

	err = fmt.Errorf("error deactivating user %s! Status code: %d", user, resp.StatusCode)
	return false, resp.StatusCode, err
}

// GIMObtainUsers deactivate an user
func GIMObtainUsers() (*[]UserTuple, error) {

	var responsePayload GIMUsersPayload
	cred, err := GIMGetCredentials(string(credentialApp.Buffer()))

	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("https://gim.stone.com.br/api/management/%s/users/", cred.Login), nil)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", cred.Password))

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

		users, err := GIMPaginateUsers(&responsePayload, responsePayload.LastPage)

		return &users, nil
	}
	err = fmt.Errorf("error obtaining GIM users! Status code: %d", resp.StatusCode)
	return nil, err
}

// GIMPaginateUsers paginates GIM users
func GIMPaginateUsers(usersPayload *GIMUsersPayload, pageCount int) ([]UserTuple, error) {

	var responsePayload GIMUsersPayload
	var activeUsers []UserTuple
	cred, err := GIMGetCredentials(string(credentialApp.Buffer()))

	if err != nil {
		return nil, err
	}

	client := &http.Client{}

	for i := 2; i <= pageCount; i++ {
		req, err := http.NewRequest("GET", fmt.Sprintf("https://gim.stone.com.br/api/management/%s/users?page=%s", cred.Login, strconv.Itoa(i)), nil)
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", cred.Password))

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

			filterResult := GIMFilterActiveusers(responsePayload.Users)

			if err != nil {
				return nil, err
			}

			activeUsers = append(activeUsers, filterResult...)

		} else {
			err = fmt.Errorf("error obtaining GIM users! Page: %d Status code: %d", i, resp.StatusCode)
			return nil, err
		}
	}
	return activeUsers, nil
}

// GIMFilterActiveusers return only active GIM users
func GIMFilterActiveusers(users []GIMUser) []UserTuple {

	var activeUsers []UserTuple

	for _, user := range users {
		if user.Active {
			activeUsers = append(activeUsers, UserTuple{user.Email, user.Comment})
		}
	}
	return activeUsers
}

func gimInviteCommand(md map[string]string, ev *slack.MessageEvent) {

	avalid, _ := GIMValidateApplication(md)

	if !avalid {
		PostMessage(ev.Channel, fmt.Sprintf("@%s nenhuma aplicação especificada e aplicação padrão não configurada\n"+
			"Utilize `gim set default application <application>` "+
			"ou invoque novamente o comando especificando a conta", ev.Username))
		return
	}

	role := strings.TrimSpace(md["role"])
	users := StripMailTo(md["users"])
	cpf := strings.TrimSpace(md["cpf"])
	name := strings.TrimSpace(md["name"])

	roles := []string{"standard", "readonly", "financial_admin", "admin"}

	PostMessage(ev.Channel, role+"\n"+users+"\n"+cpf+"\n"+name)

	if !stringInSlice(role, roles) {
		PostMessage(ev.Channel, "Role "+role+" inválida")
		return
	}

	status, _ := giminviteusers(name, users, cpf, role)

	if !status {
		PostMessage(ev.Channel, "Ocorreu um erro ao cadastrar o usuário: "+users)
		return
	}

	PostMessage(ev.Channel, "Usuário "+users+" cadastrado com sucesso")
}

func giminviteusers(name string, email string, cpf string, role string) (bool, error) {
	cred, err := GIMGetCredentials(string(credentialApp.Buffer()))
	apiKey, _ := memguard.NewImmutableFromBytes([]byte(cred.Password))
	appKey, _ := memguard.NewImmutableFromBytes([]byte(cred.Login))

	client := gimclient.NewClient(apiKey, appKey)
	resp, err := client.GetUser(email)

	// Check if user already exists
	checkUser, err := handleResponse(resp.StatusCode, err, 400, "User not found, you may proceed")
	if !checkUser {
		return false, err
		apiKey.Destroy()
		appKey.Destroy()
	}

	// Generate secret
	secret := client.GenerateSecret()

	// Secret Decoded
	decsecret := client.DecodeSecret(secret)
	// Add user to app
	fmt.Println("\nAdding user to app...")
	resp, err = client.AddUserToApp(email, name, decsecret, cpf)
	checkAdd, _ := handleResponse(resp.StatusCode, err, 201, "User created")
	if !checkAdd {
		return false, err
		apiKey.Destroy()
		appKey.Destroy()
	}

	// Add role to user
	fmt.Println("\nAdding role to user...")
	resp, err = client.AddRoleToUser(email, name, role)
	checkRole, _ := handleResponse(resp.StatusCode, err, 200, "Role "+role+" added successfully")
	if !checkRole {
		return false, err
		apiKey.Destroy()
		appKey.Destroy()
	}

	// Requesting email send by sendgrid
	from := mail.NewEmail("Secbot", "secbot@pagar.me")
	subject := "Pagar.me - Acesso Dashboard Admin 2FA"
	to := mail.NewEmail("", strings.TrimSuffix(email, "\n"))
	plainTextContent := "and easy to do anywhere, even with Go"
	linkQRCode := "https://www.google.com/chart?chs=250x250&chld=M|0&cht=qr&chl=otpauth://totp/Dashboard%20Admin:" + strings.TrimSuffix(email, "\n") + "?secret=" + secret + "&issuer=Pagarme"
	htmlContent := "<strong><br>Bem vindo a Dash Admin<br></strong>Faça o download do Authy, crie uma nova conta e escaneie QRcode abaixo ou insira manualmente o código <strong>" + secret + "</strong><br><img width=\"250\" height=\"250\" src=\"" + linkQRCode + "\"><br><br><br>Security Team - Pagar.me"
	message := mail.NewSingleEmail(from, subject, to, plainTextContent, htmlContent)
	sgclient := sendgrid.NewSendClient(string(Sendkey.Buffer()))
	response, err := sgclient.Send(message)
	checkSend, _ := handleResponse(response.StatusCode, err, 202, " Email send requested (sendgrid)\n")
	if !checkSend {
		return false, err
		apiKey.Destroy()
		appKey.Destroy()
	}
	defer memguard.DestroyAll()
	apiKey.Destroy()
	appKey.Destroy()
	return true, nil
}

func gimDeleteCPFCommand(md map[string]string, ev *slack.MessageEvent) {

	avalid, _ := GIMValidateApplication(md)

	if !avalid {
		PostMessage(ev.Channel, fmt.Sprintf("@%s nenhuma aplicação especificada e aplicação padrão não configurada\n"+
			"Utilize `gim set default application <application>` "+
			"ou invoque novamente o comando especificando a conta", ev.Username))
		return
	}

	var cpfs []string

	for _, v := range strings.Split(md["cpf"], " ") {
		cpfs = append(cpfs, v)
	}

	PostMessage(ev.Channel, fmt.Sprintf("@%s Desativando os seguintes CPFs: %s", ev.Username, strings.Join(cpfs, " ")))

	var desactive []string

	var failed []GenericError

	gimUsers, _ := GIMObtainUsers()
	for _, cpf := range cpfs {
		for _, user := range *gimUsers {
			if strings.Contains(user.Comment, cpf) {
				status, statuscode, _ := GIMDeactivateUser(user.Email)
				if !status {
					failed = append(failed, GenericError{Key: user.Email,
						Error: fmt.Sprintf("Ocorreu um erro ao desativar o usuário: status code: %s",
							statuscode)})
					continue
				}
				desactive = append(desactive, user.Email)
			}
		}
	}

	var msg = fmt.Sprintf("@%s *### Resultado ###*\n", ev.Username)

	if len(desactive) > 0 {
		msg += fmt.Sprintf("*Usuários Desativados*\n%s\n", strings.Join(desactive, " "))
	}
	if len(failed) > 0 {
		msg += fmt.Sprintf("*Erros*\n")
		for _, v := range failed {
			msg += fmt.Sprintf("%s - `%s`\n", v.Key, v.Error)
		}
	} else {
		msg += fmt.Sprintf("*Erros*\n")
		for _, cpf := range cpfs {
			msg += fmt.Sprintf("`CPF %s não existe na aplicação`\n", cpf)
		}
	}
	PostMessage(ev.Channel, msg)
}

func handleResponse(statusCode int, err error, successCode int, successMessage string) (bool, error) {

	if err != nil {
		fmt.Println("Errored when sending request to the server")
		return false, err
	} else if statusCode == successCode {
		fmt.Printf("%v!", successMessage)
		return true, nil
	} else {
		fmt.Println("Request failed!")
		fmt.Println(statusCode)
		return false, err
	}
}
