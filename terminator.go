package secbot

import (
	"fmt"
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
	var terminatedUsers, notTerminatedUsers, terminatedNotInserted []string

	for {
		emails, _, err := HandleGDriveFile()

		if err != nil {
			PostMessage(logs_channel, err.Error())

			logger.WithFields(logrus.Fields{
				"prefix": "HandleGDriveFile",
				"error":  err.Error(),
			}).Error("Error handling the GDrive file")

		} else {
			PostMessage(logs_channel, fmt.Sprintf("Will now terminate the inactive users"))
			notTerminated, err := FindNotTerminated(emails)

			if err != nil {
				PostMessage(logs_channel, err.Error())

				logger.WithFields(logrus.Fields{
					"prefix": "FindNotTerminated",
					"error":  err.Error(),
				}).Error("Error obtaining users to terminate")
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

						_, err := TrackTerminated(email)

						if err != nil {
							terminatedNotInserted = append(terminatedNotInserted, email)
						}
					}
				}
			}
		}

		PostMessage(logs_channel, fmt.Sprintf("[TERMINATOR] Usuários não desativados por motivo de erro : %s", strings.Join(notTerminatedUsers, " ")))
		PostMessage(logs_channel, fmt.Sprintf("[TERMINATOR] Usuários desativados e não registrados no banco de dados : %s", strings.Join(terminatedNotInserted, " ")))
		PostMessage(logs_channel, fmt.Sprintf("[TERMINATOR] Usuários desativados e registrados no banco de dados: %s", strings.Join(terminatedUsers, " ")))

		notTerminatedUsers, terminatedNotInserted, terminatedUsers = nil, nil, nil

		time.Sleep(86400 * time.Second)
	}
}
