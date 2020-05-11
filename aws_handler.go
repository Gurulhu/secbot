package secbot

import (
	"errors"
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/directoryservice"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/go-ini/ini"
	"github.com/nlopes/slack"
	sendgrid "github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"github.com/sirupsen/logrus"
	"github.com/tebeka/selenium"
	"github.com/tebeka/selenium/chrome"
)

var credentials_path = fmt.Sprintf("%s/.aws/credentials", GetHome())

var aws_regions []AWSRegion

type AWSRegion struct {
	Name        string
	Description string
}

type AWSInstance struct {
	AMI        string
	KeyPair    string
	PrivateIP  string
	PublicIP   string
	ID         string
	Tags       []*ec2.Tag
	LaunchTime time.Time
	Name       string
	Account    string
	Region     string
}

func AWSHandlerStart() {

	RegisterHandler("aws")

	AddCommand(Command{
		Regex:       regexp.MustCompile("aws (?P<command>list accounts)"),
		Help:        "Obtém a lista de contas",
		Handler:     AWSListAccountsCommand,
		Usage:       "aws list accounts",
		HandlerName: "aws"})

	AddCommand(Command{
		Regex:       regexp.MustCompile("aws (?P<command>list regions)"),
		Help:        "Obtém a lista de regiões",
		Handler:     AWSListRegionsCommand,
		Usage:       "aws list regions",
		HandlerName: "aws"})

	AddCommand(Command{
		Regex:       regexp.MustCompile("aws (?P<account>\\S+) (?P<region>\\S+) (?P<command>list instances)"),
		Help:        "Obtém a lista das instâncias e suas roles",
		Handler:     AWSListInstancesCommand,
		HandlerName: "aws",
		Usage:       "aws <account> <region> list instances",
		Parameters: map[string]string{
			"account": "\\S+",
			"region":  "\\S+",
		}})

	AddCommand(Command{
		Regex:       regexp.MustCompile("aws (?P<account>\\S+) (?P<region>\\S+) (?P<command>whoisip) (?P<address>\\S+)"),
		Help:        "Obtém a role da máquina <address>",
		Handler:     AWSWhoisIPCommand,
		HandlerName: "aws",
		Usage:       "aws <account> <region> whoisip <address>",
		Parameters: map[string]string{
			"account": "\\S+",
			"region":  "\\S+",
			"address": "\\S+",
		}})

	AddCommand(Command{
		Regex:       regexp.MustCompile("aws (?P<account>\\S+) (?P<region>\\S+) (?P<command>whois) (?P<name>\\S+)"),
		Help:        "Obtém os IPs das máquinas com a role <name>",
		Handler:     AWSWhoisCommand,
		HandlerName: "aws",
		Usage:       "aws <account> <region> whois <name>",
		Parameters: map[string]string{
			"account": "\\S+",
			"region":  "\\S+",
			"name":    "\\S+",
		}})

	AddCommand(Command{
		Regex:       regexp.MustCompile("aws (?P<command>findip) (?P<address>\\S+)"),
		Help:        "Obtém a role da máquina <address> em todas as regiões de todas as contas",
		Handler:     AWSFindIPCommand,
		HandlerName: "aws",
		Usage:       "aws findip <address>",
		Parameters: map[string]string{
			"address": "\\S+",
		}})

	AddCommand(Command{
		Regex:       regexp.MustCompile("aws (?P<command>find) (?P<name>\\S+)"),
		Help:        "Obtém os IPs das máquinas com a role <name> em todas as regiões de todas as contas",
		Handler:     AWSFindCommand,
		HandlerName: "aws",
		Usage:       "aws find <name>",
		Parameters: map[string]string{
			"name": "\\S+",
		}})

	AddCommand(Command{
		Regex:              regexp.MustCompile("aws (?P<command>recover) (?P<users>.*)"),
		Help:               "Envia email de recuperação de senha para <users>",
		Usage:              "aws recover <users>",
		Handler:            AWSecoverCommand,
		RequiredPermission: "aws_reset",
		HandlerName:        "aws",
		Parameters: map[string]string{
			"users": ".*",
		}})

	aws_regions = append(aws_regions, AWSRegion{Name: "us-east-1", Description: "US East (N. Virginia)"})

	aws_regions = append(aws_regions, AWSRegion{Name: "us-east-2", Description: "US East (Ohio)"})

	aws_regions = append(aws_regions, AWSRegion{Name: "us-west-1", Description: "US West (N. California)"})

	aws_regions = append(aws_regions, AWSRegion{Name: "us-west-2", Description: "US West (Oregon)"})

	aws_regions = append(aws_regions, AWSRegion{Name: "ca-central-1", Description: "Canada (Central)"})

	aws_regions = append(aws_regions, AWSRegion{Name: "eu-central-1", Description: "EU (Frankfurt)"})

	aws_regions = append(aws_regions, AWSRegion{Name: "eu-west-1", Description: "EU (Ireland)"})

	aws_regions = append(aws_regions, AWSRegion{Name: "eu-west-2", Description: "EU (London)"})

	aws_regions = append(aws_regions, AWSRegion{Name: "eu-west-3", Description: "EU (Paris)"})

	aws_regions = append(aws_regions, AWSRegion{Name: "ap-northeast-1", Description: "Asia Pacific (Tokyo)"})

	aws_regions = append(aws_regions, AWSRegion{Name: "ap-northeast-2", Description: "Asia Pacific (Seoul)"})

	aws_regions = append(aws_regions, AWSRegion{Name: "ap-northeast-3", Description: "Asia Pacific (Osaka-Local)"})

	aws_regions = append(aws_regions, AWSRegion{Name: "ap-southeast-1", Description: "Asia Pacific (Singapore)"})

	aws_regions = append(aws_regions, AWSRegion{Name: "ap-southeast-2", Description: "Asia Pacific (Sydney)"})

	aws_regions = append(aws_regions, AWSRegion{Name: "ap-south-1", Description: "Asia Pacific (Mumbai)"})

	aws_regions = append(aws_regions, AWSRegion{Name: "sa-east-1", Description: "South America (São Paulo)"})

}

func AWSListRegions() []string {
	regions := AWSGetRegions()

	var reglist []string

	for _, v := range regions {
		reglist = append(reglist, v.Name)
	}

	return reglist
}

func AWSHasRegion(region string) bool {
	regions := AWSListRegions()

	for _, v := range regions {
		if v == region {
			return true
		}
	}

	return false
}

func AWSHasProfile(account string) bool {
	profiles := AWSListProfiles()

	for _, v := range profiles {
		if v == account {
			return true
		}
	}

	return false
}

/*
Gets the account list.

HandlerName

 aws

Regex

 aws (?P<command>list accounts)

Usage

 aws list accounts
*/
func AWSListAccountsCommand(md map[string]string, ev *slack.MessageEvent) {

	profiles := AWSListProfiles()

	var msg = fmt.Sprintf("@%s\n*### Lista de Perfis AWS ###*\n", ev.Username)

	for _, v := range profiles {
		msg += fmt.Sprintf("\n%s", v)
	}

	PostMessage(ev.Channel, msg)

}

/*
Gets instances containing <name> in the Name tag.

HandlerName
 aws

Regex

 aws (?P<account>\\S+) (?P<region>\\S+) (?P<command>whois) (?P<name>\\S+)

Usage
 aws <account> <region> whois <name>
*/
func AWSWhoisCommand(md map[string]string, ev *slack.MessageEvent) {
	if !AWSHasRegion(md["region"]) {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Região `%s` inválida, os valores possíveis são:\n%s",
			ev.Username, md["region"], strings.Join(AWSListRegions(), "\n")))
		return
	}

	if !AWSHasProfile(md["account"]) {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Conta `%s` inválida, os valores possíveis são:\n%s",
			ev.Username, md["account"], strings.Join(AWSListProfiles(), "\n")))
		return
	}

	instances, err := AWSListInstances(md["account"], md["region"])

	if err != nil {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Ocorreu um erro processando a solicitação: %s",
			ev.Username, err.Error()))
	} else {

		var msg = fmt.Sprintf("@%s\n*### Lista de Instâncias AWS na conta %s com o nome %s ###*\n", ev.Username, md["account"], md["name"])

		var instance AWSInstance

		for _, i := range instances {
			for _, v := range i.Tags {
				if *v.Key == "Name" {
					if *v.Value == md["name"] {
						instance = i
						break
					}
				}
			}
		}

		if len(instance.ID) > 0 {
			msg += fmt.Sprintf("\n*ID:* %v | *Creation Date:* %v | *Private IP:* %v | *Public IP:* %v | "+
				"*Key Pair:* %v | *Name:* %v", instance.ID, instance.LaunchTime, instance.PrivateIP, instance.PublicIP, instance.KeyPair, instance.Name)
			PostMessage(ev.Channel, msg)
		} else {
			PostMessage(ev.Channel, fmt.Sprintf("@%s Instância com o nome `%s` não encontrada na conta `%s`", ev.Username, md["name"], md["account"]))
		}

	}
}

/*
Gets instances with the <address> IP.

HandlerName

 aws

Regex

 aws (?P<account>\\S+) (?P<region>\\S+) (?P<command>whoisip) (?P<address>\\S+)

Usage

 aws <account> <region> whoisip <address>
*/
func AWSWhoisIPCommand(md map[string]string, ev *slack.MessageEvent) {
	if !AWSHasRegion(md["region"]) {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Região `%s` inválida, os valores possíveis são:\n%s",
			ev.Username, md["region"], strings.Join(AWSListRegions(), "\n")))
		return
	}

	if !AWSHasProfile(md["account"]) {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Conta `%s` inválida, os valores possíveis são:\n%s",
			ev.Username, md["account"], strings.Join(AWSListProfiles(), "\n")))
		return
	}

	instances, err := AWSListInstances(md["account"], md["region"])

	if err != nil {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Ocorreu um erro processando a solicitação: %s",
			ev.Username, err.Error()))
	} else {

		var msg = fmt.Sprintf("@%s\n*### Lista de Instâncias AWS na conta %s com IP %s ###*\n", ev.Username, md["account"], md["address"])

		var instance AWSInstance

		for _, v := range instances {
			if v.PrivateIP == md["address"] || v.PublicIP == md["address"] {
				instance = v
				break
			}
		}

		if len(instance.ID) > 0 {
			msg += fmt.Sprintf("\n*ID:* %v | *Creation Date:* %v | *Private IP:* %v | *Public IP:* %v | "+
				"*Key Pair:* %v | *Name:* %v", instance.ID, instance.LaunchTime, instance.PrivateIP, instance.PublicIP, instance.KeyPair, instance.Name)
			PostMessage(ev.Channel, msg)
		} else {
			PostMessage(ev.Channel, fmt.Sprintf("@%s Instância com IP `%s` não encontrada na conta `%s`", ev.Username, md["address"], md["account"]))
		}

	}
}

/*
Gets instances containing <name> in the Name tag for all accounts.

HandlerName

 aws

Regex

 aws (?P<command>find) (?P<name>\\S+)

Usage

 aws find <name>
*/
func AWSFindCommand(md map[string]string, ev *slack.MessageEvent) {
	PostMessage(ev.Channel, fmt.Sprintf("@%s procurando instâncias com o nome `%s`", ev.Username, md["name"]))

	func(md map[string]string, ev *slack.MessageEvent) {
		accounts := AWSListProfiles()
		regions := AWSGetRegions()

		for _, acc := range accounts {
			for _, region := range regions {
				go func(acc string, region string, iname string) {

					instances, err := AWSListInstances(acc, region)

					if err != nil {
						//PostMessage(ev.Channel, fmt.Sprintf("@%s Ocorreu um erro processando a solicitação para a conta %s: %s",
						//	ev.Username, acc, err.Error()))
					} else {

						var ninstances []AWSInstance

						for _, i := range instances {
							for _, v := range i.Tags {
								if *v.Key == "Name" {
									if strings.Contains(*v.Value, iname) {
										ninstances = append(ninstances, i)

									}
								}
							}
						}

						if len(ninstances) > 0 {

							for _, inst := range ninstances {
								if len(inst.ID) > 0 {
									PostMessage(ev.Channel, fmt.Sprintf("\n*Conta:* %s | *Região:* %s | *ID:* %v | *Creation Date:* %v | *Private IP:* %v | *Public IP:* %v | "+
										"*Key Pair:* %v | *Name:* %v", inst.Account, inst.Region, inst.ID, inst.LaunchTime, inst.PrivateIP, inst.PublicIP, inst.KeyPair, inst.Name))
								}

							}

						}

					}

				}(acc, region.Name, md["name"])
			}
		}

	}(md, ev)

}

/*
Gets instances with the <address> IP for all accounts.

HandlerName

 aws

Regex

 aws (?P<command>findip) (?P<address>\\S+)

Usage

 aws findip <address>
*/
func AWSFindIPCommand(md map[string]string, ev *slack.MessageEvent) {
	PostMessage(ev.Channel, fmt.Sprintf("@%s procurando instâncias com o IP `%s`", ev.Username, md["address"]))

	func(md map[string]string, ev *slack.MessageEvent) {
		accounts := AWSListProfiles()
		regions := AWSGetRegions()

		for _, acc := range accounts {
			for _, region := range regions {
				go func(acc string, region string, iaddress string) {

					instances, err := AWSListInstances(acc, region)

					if err != nil {
						//PostMessage(ev.Channel, fmt.Sprintf("@%s Ocorreu um erro processando a solicitação para a conta %s: %s",
						//	ev.Username, acc, err.Error()))
					} else {

						var ninstances []AWSInstance

						for _, i := range instances {
							if i.PrivateIP == iaddress || i.PublicIP == iaddress {
								ninstances = append(ninstances, i)
							}
						}

						if len(ninstances) > 0 {

							for _, inst := range ninstances {
								if len(inst.ID) > 0 {
									PostMessage(ev.Channel, fmt.Sprintf("\n*Conta:* %s | *Região:* %s | *ID:* %v | *Creation Date:* %v | *Private IP:* %v | *Public IP:* %v | "+
										"*Key Pair:* %v | *Name:* %v", inst.Account, inst.Region, inst.ID, inst.LaunchTime, inst.PrivateIP, inst.PublicIP, inst.KeyPair, inst.Name))
								}

							}

						}

					}

				}(acc, region.Name, md["address"])
			}
		}

	}(md, ev)

}

/*
Gets the region list.

HandlerName
 aws

Regex
 aws (?P<command>list regions)

Usage
 aws list regions

*/
func AWSListRegionsCommand(md map[string]string, ev *slack.MessageEvent) {

	regions := AWSGetRegions()

	var msg = fmt.Sprintf("@%s\n*### Lista de Regiões AWS ###*\n", ev.Username)

	for _, v := range regions {
		msg += fmt.Sprintf("\n*%s* - %s", v.Name, v.Description)
	}

	PostMessage(ev.Channel, msg)

}

func AWSGetRegions() []AWSRegion {
	return aws_regions
}

/*
Gets the instance list.

HandlerName
 aws

Regex
 aws (?P<account>\\S+) (?P<region>\\S+) (?P<command>list instances)"

Usage
 aws <account> <region> list instances
*/
func AWSListInstancesCommand(md map[string]string, ev *slack.MessageEvent) {
	instances, err := AWSListInstances(md["account"], md["region"])

	if err != nil {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Ocorreu um erro processando a solicitação: %s",
			ev.Username, err.Error()))
	} else {

		var msg = fmt.Sprintf("@%s\n*### Lista de Instâncias AWS na conta %s ###*\n", ev.Username, md["account"])

		for _, v := range instances {
			msg += fmt.Sprintf("\n*ID:* %v | *Creation Date:* %v | *Private IP:* %v | *Public IP:* %v | "+
				"*Key Pair:* %v | *Name:* %v", v.ID, v.LaunchTime, v.PrivateIP, v.PublicIP, v.KeyPair, v.Name)
		}

		PostMessage(ev.Channel, msg)
	}
}

func AWSGetSession(account string, region string) (*session.Session, error) {
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewSharedCredentials(credentials_path, account),
	})

	if err != nil {
		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix":  "AWSGetSession",
			"caller":  caller,
			"file":    file,
			"error":   err.Error(),
			"account": account,
			"region":  region,
		}).Error("An Error Occurred")

		return nil, err
	}

	return sess, err
}

func AWSListInstances(account string, region string) ([]AWSInstance, error) {

	if !stringInSlice(account, AWSListProfiles()) {
		err := errors.New(fmt.Sprintf("Invalid account %s", account))

		return nil, err
	}

	sess, _ := AWSGetSession(account, region)

	ec2Svc := ec2.New(sess)

	result, err := ec2Svc.DescribeInstances(nil)

	if err != nil {
		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix":  "AWSListInstances",
			"caller":  caller,
			"file":    file,
			"error":   err.Error(),
			"account": account,
			"region":  region,
		}).Error("An Error Occurred")

		return nil, err
	}

	var instances []AWSInstance

	for _, v := range result.Reservations {
		for _, i := range v.Instances {
			v := AWSInstance{}
			if i.InstanceId != nil {
				v.ID = *i.InstanceId
			}
			if i.KeyName != nil {
				v.KeyPair = *i.KeyName
			}

			if i.PrivateIpAddress != nil {
				v.PrivateIP = *i.PrivateIpAddress
			}
			if i.PublicIpAddress != nil {
				v.PublicIP = *i.PublicIpAddress
			}
			if i.Tags != nil {
				v.Tags = i.Tags
			}

			for _, t := range i.Tags {
				if *t.Key == "Name" {
					v.Name = *t.Value
				}
			}

			if i.LaunchTime != nil {
				v.LaunchTime = *i.LaunchTime
			}

			v.Account = account
			v.Region = region

			instances = append(instances, v)
		}
	}

	return instances, err
}

func AWSListProfiles() []string {
	cfg, err := ini.Load(credentials_path)

	var sections []string

	if err != nil {
		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix": "AWSListProfiles",
			"caller": caller,
			"file":   file,
			"error":  err.Error(),
		}).Error("An Error Occurred")
	} else {
		for _, v := range cfg.Sections() {
			if v.Name() != "DEFAULT" {
				sections = append(sections, v.Name())
			}

		}
	}

	return sections
}

func AWSecoverCommand(md map[string]string, ev *slack.MessageEvent) {

	var users []string

	for _, v := range strings.Split(md["users"], " ") {
		users = append(users, StripMailTo(v))
	}

	PostMessage(ev.Channel, fmt.Sprintf("@%s Recuperando senha dos seguintes usuários: %s", ev.Username, strings.Join(users, " ")))

	var recovered []string

	var failed []GenericError

	for _, user := range users {

		Reset, err := AWSReset(user)

		if err != nil {
			failed = append(failed, GenericError{Key: user,
				Error: fmt.Sprintf("Ocorreu um erro resetando a senha do usuário: %s",
					err.Error())})
			continue
		}

		if Reset {
			recovered = append(recovered, user)
			continue
		} else {
			failed = append(failed, GenericError{Key: user, Error: fmt.Sprintf("Erro: %s",
				err)})
			continue
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

func AWSReset(email string) (bool, error) {

	port := 53312
	var opts []selenium.ServiceOption
	service, err := selenium.NewChromeDriverService("chromedriver", port, opts...)
	defer service.Stop()

	caps := selenium.Capabilities{
		"browserName": "chrome",
	}
	args := []string{"--headless"}
	caps.AddChrome(chrome.Capabilities{
		Args: args,
	})
	Driver, err := selenium.NewRemote(caps, "http://127.0.0.1:"+strconv.Itoa(port)+"/wd/hub")
	if err != nil {
		fmt.Println(err)
		return false, err
	}

	Driver.Get("https://viacry.pt")
	message1, _ := Driver.FindElement(selenium.ByID, "message")
	passwd := GeneratePassword(32)
	err = message1.SendKeys(passwd)
	if err != nil {
		fmt.Println(err)
		return false, err
	}
	click, _ := Driver.FindElement(selenium.ByXPATH, "//button[@type='submit']")
	click.Click()
	time.Sleep(2 * time.Second)

	Html, _ := Driver.PageSource()
	link := strings.Split(Html, "this.value = '")
	link = strings.Split(link[1], "'")

	user := strings.Split(email, "@")

	from := mail.NewEmail("Security Pagarme", "security@pagar.me")
	subject := "[Security][Pagar.me] Credencias SSO Auth0"
	to := mail.NewEmail("", strings.TrimSuffix(email, "<br>"))
	plainTextContent := "Pagar.me"
	htmlContent := fmt.Sprintf("Suas credenciais foram geradas para o acesso ao AUth0.<br><br>Utilize este link para o acesso: %s .<br><br>O link para a senha será acessivel somente uma vez, portanto, salve a senha em seu cofre.<br><br><br>User: %s<br>Password: %s <br><br><br>Security Team - Pagar.me", string(LinkSSo), user[0], link[0])
	message := mail.NewSingleEmail(from, subject, to, plainTextContent, htmlContent)
	sgclient := sendgrid.NewSendClient(string(Sendkey.Buffer()))
	response, err := sgclient.Send(message)

	if response.StatusCode != 202 {
		fmt.Println(response)
		return false, nil
	} else if err != nil {
		fmt.Println(err)
		return false, err
	}

	_, err = DSReset("security", "us-east-1", user[0], passwd)
	if err != nil {
		fmt.Println(err)
		return false, err
	}

	return true, nil

}

func DSReset(account string, region string, UserN string, NPasswd string) (*directoryservice.ResetUserPasswordOutput, error) {

	if !stringInSlice(account, AWSListProfiles()) {
		err := errors.New(fmt.Sprintf("Invalid account %s", account))

		return nil, err
	}

	sess, _ := AWSGetSession(account, region)
	ds := directoryservice.New(sess)
	result, err := ds.ResetUserPassword(&directoryservice.ResetUserPasswordInput{
		DirectoryId: &DSid,
		NewPassword: &NPasswd,
		UserName:    &UserN})

	return result, err
}

func GeneratePassword(length int) string {
	rand.Seed(time.Now().UnixNano())
	digits := "0123456789"
	specials := "~=+%^*/()[]{}/!@#$?|"
	all := "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		digits + specials
	buf := make([]byte, length)
	buf[0] = digits[rand.Intn(len(digits))]
	buf[1] = specials[rand.Intn(len(specials))]
	for i := 2; i < length; i++ {
		buf[i] = all[rand.Intn(len(all))]
	}
	rand.Shuffle(len(buf), func(i, j int) {
		buf[i], buf[j] = buf[j], buf[i]
	})
	str := string(buf)
	return str
}
