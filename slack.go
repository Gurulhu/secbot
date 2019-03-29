package secbot

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nlopes/slack"
	"github.com/sirupsen/logrus"
)

var slack_group_map = make(map[string]*slack.Group)
var slack_channel_map = make(map[string]*slack.Channel)
var slack_user_map = make(map[string]*slack.User)

type Slack struct {
	Ok    bool `json:"ok"`
	Items []struct {
		ID      string `json:"id"`
		Profile struct {
			Email string `json:"email"`
		} `json:"profile"`
	} `json:"items"`
}

var host = os.Getenv("SLACK_HOST")
var cookie = os.Getenv("SLACK_COOKIE")
var client = &http.Client{}

/*
Request with the necessary headers
*/
func requests(Method string, url string, body io.Reader, ConType string) (*http.Response, error) {
	req, _ := http.NewRequest(Method, url, body)
	req.Header.Set("Origin", host)
	req.Header.Set("Accept-Language", "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Authority", strings.Replace(host, "https://", "", -1))
	req.Header.Set("Cookie", cookie)
	req.Header.Set("X-Slack-Version-Ts", "1524100347")
	if Method == "POST" {
		req.Header.Add("Content-Type", ConType)
	}
	return client.Do(req)
}

/*
Get token Slack for use in request
*/
func getoken() string {
	reqtoken, err := requests("GET", host+"/admin", nil, "")
	if err != nil {
		return "Error"
	}
	tokenbodyBytes, _ := ioutil.ReadAll(reqtoken.Body)
	split1 := strings.SplitAfter(string(tokenbodyBytes), "api_token: \"")[1]
	token := strings.Split(split1, "\",")[0]
	return token
}

/*
Send invate to users in Slack
*/
func invite(email string) bool {
	err := api.InviteToTeam("users", "", "", email)
	if err != nil {
		return false
	}
	return true
}

/*
Delete users in Slack with email
*/
func delUser(UserID string) bool {
	err := api.DisableUser("users", UserID)
	if err != nil {
		return false
	}
	return true
}

/*
Checks if a message was directed to the bot by checking if it starts with the bot ID.

See: https://godoc.org/github.com/pagarme/secbot/#GetID
*/
func AtBot(message string) bool {
	if strings.HasPrefix(message, fmt.Sprintf("<@%s>", botid)) {
		return true
	}
	return false
}

/*
Gets an slack.Group object by it's ID
*/
func GetGroup(id string) (*slack.Group, error) {

	if val, ok := slack_group_map[id]; ok {
		return val, nil
	}

	group, err := api.GetGroupInfo(id)

	if err != nil {
		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix": "GetGroup",
			"caller": caller,
			"file":   file,
			"group":  id,
			"error":  err.Error(),
		}).Error("An Error Occurred")
	}

	slack_group_map[id] = group

	return group, err
}

/*
Gets an slack.Channel object by it's ID
*/
func GetChannel(id string) (*slack.Channel, error) {

	if val, ok := slack_channel_map[id]; ok {
		return val, nil
	}

	channel, err := api.GetChannelInfo(id)

	if err != nil {
		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix":  "GetChannel",
			"caller":  caller,
			"file":    file,
			"channel": id,
			"error":   err.Error(),
		}).Error("An Error Occurred")
	}

	slack_channel_map[id] = channel

	return channel, err
}

/*
Gets an slack.User object by it's ID
*/
func GetUser(id string) (*slack.User, error) {
	if val, ok := slack_user_map[id]; ok {
		return val, nil
	}

	user, err := api.GetUserInfo(id)

	if err != nil {
		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix": "GetUser",
			"caller": caller,
			"file":   file,
			"user":   id,
			"error":  err.Error(),
		}).Error("An Error Occurred")
	}

	slack_user_map[id] = user

	return user, err
}

// GetID the bot ID by looking for a user with a matching username as the one set in botname global variable.
func GetID(username string) (string, error) {
	users, err := api.GetUsers()

	if err != nil {
		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix": "GetID",
			"caller": caller,
			"file":   file,
			"error":  err.Error(),
		}).Error("An Error Occurred")
		return "", err
	}

	for _, user := range users {
		if user.Name == username {
			return user.ID, nil
		}

	}

	return "", nil
}

/*
This function in called on RTM *slack.ConnectedEvent as a goroutine.

It periodically checks for new channels and joins them.
*/
func JoinChannels(notify bool) {
	for {
		channels, err := api.GetChannels(true)

		if err != nil {
			caller, file := GetCaller()
			logger.WithFields(logrus.Fields{
				"prefix": "JoinChannels",
				"caller": caller,
				"file":   file,
				"error":  err.Error(),
			}).Error("An Error Occurred")
			continue
		}

		for _, channel := range channels {
			if !channel.IsMember {

				logger.WithFields(logrus.Fields{
					"prefix":  "JoinChannels",
					"channel": channel.Name,
				}).Info("Joining Channel")

				api.JoinChannel(channel.Name)

				if notify {
					PostMessage(channel.Name, "Every move you make\nEvery step you take\nI'll be watching you")
				}

			}
		}

		time.Sleep(100 * time.Second)

	}

}

/*
Simple helper function to post a message to a channel.
*/
func PostMessage(channel string, message string) {
	api.PostMessage(channel, message, slack.PostMessageParameters{AsUser: true, LinkNames: 1, Markdown: true})

}

/*
Simple helper function to post an epheremal message to an user.
*/
func PostEphemeralMessage(channel string, user string, message string) {
	params := slack.NewPostMessageParameters()

	api.PostEphemeral(channel, user, slack.MsgOptionText(message, params.EscapeText),
		slack.MsgOptionPostMessageParameters(slack.PostMessageParameters{AsUser: true, LinkNames: 1, Markdown: true}))
}

/*
Simple helper function to delete a message.
*/
func DeleteMessage(ev *slack.MessageEvent) {
	err := ev.SubMessage
	if err == nil {
		api.DeleteMessage(ev.Channel, ev.Timestamp)
	} else {
		api.DeleteMessage(ev.Channel, ev.SubMessage.Timestamp)
	}

}

/*
Simple helper function to remove mailto formatting from an string.
*/
func StripMailTo(text string) string {
	if strings.Contains(text, ":") && strings.Contains(text, "|") {
		return strings.Split(strings.Split(text, ":")[1], "|")[0]
	} else {
		return text
	}
}

// StripUserId Simple helper function to remove ID formatting from an string.
func StripUserId(text string) string {
	return strings.Split(strings.Split(text, "<@")[2], ">")[0]
}

/*
Simple helper function to remove url formatting from an string.
*/
func StripURL(text string) string {
	var t = text

	if strings.Contains(t, "|") {
		t = strings.Split(t, "|")[1]
	}

	if strings.Contains(t, "<") {
		t = strings.Split(t, "<")[1]
	}

	if strings.Contains(t, ">") {
		t = strings.Split(t, ">")[0]
	}

	return t
}
