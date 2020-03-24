package secbot

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// TerminatorHandlerStart handler for the terminate utilities
func TerminatorHandlerStart() {

	RegisterHandler("terminator")

	go Terminate()
}

// Terminate handle the terminations of inactive users
func Terminate() {

	for {
		users, err := HandleGDriveFile()
		emails := make([]string, 0, len(*users))
		for e := range *users {
			emails = append(emails, e)
		}

		if err != nil {
			PostMessage(logs_channel, err.Error())

			logger.WithFields(logrus.Fields{
				"prefix": "HandleGDriveFile",
				"error":  err.Error(),
			}).Error("Error handling the GDrive file")

			PostMessage(logs_channel, fmt.Sprintf("[GOOGLE DRIVE] Erro ao processar arquivo: %s", err.Error()))
		} else {
			TerminateGIMUsers(users)
			err := TerminateMetabaseUsers(&emails)

			if err != nil {
				PostMessage(logs_channel, fmt.Sprintf("[METABASE] Erro ao executar rotina de desativação de usuários: %s", err.Error()))
			}
		}
		time.Sleep(86400 * time.Second)
	}
}

// TerminateGIMUsers terminate GIM Users using its REST API
func TerminateGIMUsers(users *map[string]string) {

	var terminatedUsers, notTerminatedUsers, terminatedNotInserted []string

	emails := make([]string, 0, len(*users))
	for e := range *users {
		emails = append(emails, e)
	}

	gimUsers, err := GIMObtainUsers()

	if err != nil {
		PostMessage(logs_channel, err.Error())

		logger.WithFields(logrus.Fields{
			"prefix": "GIMObtainUsers",
			"error":  err.Error(),
		}).Error("Error obtaining GIM users from API")
	} else {
		notTerminatedAlready, err := FindGIMNotTerminated(&emails)
		notTerminated := obtainCPFAssociatedEmails(*users, notTerminatedAlready, gimUsers)

		if err != nil {
			PostMessage(logs_channel, err.Error())

			logger.WithFields(logrus.Fields{
				"prefix": "FindGIMNotTerminated",
				"error":  err.Error(),
			}).Error("Error obtaining GIM users from database")
		} else {

			for _, email := range notTerminated {
				_, err := GIMDeactivateUser(email)

				if err != nil {
					notTerminatedUsers = append(notTerminatedUsers, email)

					logger.WithFields(logrus.Fields{
						"prefix": "GIMDeactivateUser",
						"error":  err.Error(),
					}).Error(fmt.Sprintf("Error terminating user %s", email))
				} else {
					terminatedUsers = append(terminatedUsers, email)

					_, err := TrackGIMTerminated(email)

					if err != nil {
						terminatedNotInserted = append(terminatedNotInserted, email)
					}
				}
			}
			TerminateNotifyChannel("GIM", terminatedUsers, terminatedNotInserted, notTerminatedUsers)
		}
	}
}

// TerminateMetabaseUsers terminate Metabase Users using its REST API
func TerminateMetabaseUsers(emails *[]string) error {

	var terminatedUsers, notTerminatedUsers, terminatedNotInserted []string

	notTerminated, err := FindMetabaseNotTerminated(emails)

	if err != nil {
		PostMessage(logs_channel, err.Error())

		logger.WithFields(logrus.Fields{
			"prefix": "FindMetabaseNotTerminated",
			"error":  err.Error(),
		}).Error("Error obtaining Metabase users to terminate")
	} else {
		token, err := ObtainMetabaseToken()

		if err != nil {
			logger.WithFields(logrus.Fields{
				"prefix": "ObtainMetabaseToken",
				"error":  err.Error(),
			}).Error("Error refreshing Metabase token")

			return err
		}
		users, err := ObtainMetabaseUsers(*token)

		if err != nil {
			logger.WithFields(logrus.Fields{
				"prefix": "ObtainMetabaseUsers",
				"error":  err.Error(),
			}).Error("Error obtaining Metabase users")

			return err
		}
		usersMap, err := FindMetabaseNotTerminatedID(notTerminated, *users)

		for email, id := range usersMap {
			_, err = DeactivateMetabaseUser(strconv.Itoa(id), *token)

			if err != nil {
				notTerminatedUsers = append(notTerminatedUsers, email)

				logger.WithFields(logrus.Fields{
					"prefix": "DeactivateMetabaseUser",
					"error":  err.Error(),
				}).Error(fmt.Sprintf("Error terminating user %s", email))
			} else {
				terminatedUsers = append(terminatedUsers, email)

				_, err := TrackMetabaseTerminated(email)

				if err != nil {
					terminatedNotInserted = append(terminatedNotInserted, email)
				}
			}
		}

		TerminateNotifyChannel("METABASE", terminatedUsers, terminatedNotInserted, notTerminatedUsers)
	}
	return nil
}

// TerminateNotifyChannel Notifies the channel after the tasks are done
func TerminateNotifyChannel(application string, terminated []string, notInserted []string, notTerminated []string) {

	if len(terminated) > 0 {
		PostMessage(logs_channel, fmt.Sprintf("@here [%s] Usuários desativados: %s", application, strings.Join(terminated, " ")))
	} else {
		PostMessage(logs_channel, fmt.Sprintf("[%s] Nenhum usuário pendente de desativação", application))
	}

	if len(notInserted) > 0 {
		PostMessage(logs_channel, fmt.Sprintf("[%s] Usuários desativados e não registrados no banco de dados: %s", application, strings.Join(notInserted, " ")))
	}

	if len(notTerminated) > 0 {
		PostMessage(logs_channel, fmt.Sprintf("[%s] Usuários não desativados por motivo de erro: %s", application, strings.Join(notTerminated, " ")))
	}
}

func obtainCPFAssociatedEmails(users map[string]string, notTerminated *[]string, gimUsers *[]UserTuple) []string {

	var notTerminatedCPFs []string
	var notTerminatedEmails []string
	reg, _ := regexp.Compile("[^0-9]+")

	for _, email := range *notTerminated {
		sanitizedCPF := reg.ReplaceAllString(users[email], "")
		if len(sanitizedCPF) > 0 {
			notTerminatedCPFs = append(notTerminatedCPFs, sanitizedCPF)
		}
	}

	for _, cpf := range notTerminatedCPFs {
		for _, user := range *gimUsers {
			if strings.Contains(user.Comment, cpf) {
				notTerminatedEmails = append(notTerminatedEmails, user.Email)
			}
		}
	}
	return notTerminatedEmails
}
