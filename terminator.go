package secbot

import (
	"fmt"
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
		emails, _, err := HandleGDriveFile()

		if err != nil {
			PostMessage(logs_channel, err.Error())

			logger.WithFields(logrus.Fields{
				"prefix": "HandleGDriveFile",
				"error":  err.Error(),
			}).Error("Error handling the GDrive file")

			PostMessage(logs_channel, fmt.Sprintf("[GOOGLE DRIVE] Erro ao processar arquivo: %s", err.Error()))
		} else {
			TerminateGIMUsers(emails)
			err := TerminateMetabaseUsers(emails)

			if err != nil {
				PostMessage(logs_channel, fmt.Sprintf("[METABASE] Erro ao executar rotina de desativação de usuários: %s", err.Error()))
			}
		}
		time.Sleep(86400 * time.Second)
	}
}

// TerminateGIMUsers terminate GIM Users using its REST API
func TerminateGIMUsers(emails *[]string) {

	var terminatedUsers, notTerminatedUsers, terminatedNotInserted []string

	notTerminated, err := FindGIMNotTerminated(emails)

	if err != nil {
		PostMessage(logs_channel, err.Error())

		logger.WithFields(logrus.Fields{
			"prefix": "FindGIMNotTerminated",
			"error":  err.Error(),
		}).Error("Error obtaining GIM users to terminate")
	} else {

		for _, email := range *notTerminated {
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
