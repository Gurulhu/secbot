package secbot

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/nlopes/slack"
)

func CFHandlerStart() {

	RegisterHandler("cf")

	AddCommand(Command{
		Regex:       regexp.MustCompile("cf (?P<command>list)"),
		Help:        "Lista os IPs bloqueados na Cloudflare",
		Usage:       "cf list",
		Handler:     WAFListCommand,
		HandlerName: "cf"})

	AddCommand(Command{
		Regex:              regexp.MustCompile("cf (?P<command>block) (?P<addresses>(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}\\s?)+)"),
		Help:               "Bloqueia IPs no WAF",
		Usage:              "cf block <addresses>",
		Handler:            CFBlockCommand,
		RequiredPermission: "cf",
		HandlerName:        "cf",
		Parameters: map[string]string{
			"addresses": "(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}\\s?)+)",
		}})

	AddCommand(Command{
		Regex:              regexp.MustCompile("cf (?P<command>unblock) (?P<addresses>(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}\\s?)+)"),
		Help:               "Desbloqueia IPs no WAF",
		Usage:              "cf unblock <addresses>",
		Handler:            CFUnblockCommand,
		RequiredPermission: "cf",
		HandlerName:        "cf",
		Parameters: map[string]string{
			"addresses": "(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}\\s?)+)",
		}})
}

/*
Lists blocked IPs.

HandlerName

 waf

Regex

 waf (?P<command>list)

Usage

 waf list
*/

func CFListCommand(md map[string]string, ev *slack.MessageEvent) {

	ips, err := CloudflareListBlockedIPs()

	if err != nil {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Ocorreu um erro listando os IPs: %s", ev.Username, err.Error()))
		return
	}

	PostMessage(ev.Channel, fmt.Sprintf("@%s *### Lista de IPs bloqueados ###*\n%s",
		ev.Username, strings.Join(ips, "\n")))

}

/*
Blocks the specified IPs on the account's WAF

HandlerName

 waf

RequiredPermission

 waf

Regex

 waf (?P<command>block) (?P<addresses>(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}\\s?)+)

 waf (?P<account>\\S+) (?P<region>\\S+) (?P<command>block) (?P<addresses>(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}\\s?)+)

Usage

 waf block <addresses>

 waf <account> <region> block <addresses>
*/
func CFBlockCommand(md map[string]string, ev *slack.MessageEvent) {
	var blockedIPs []string
	var alreadyBlockedIPs []string

	for _, ip := range strings.Split(md["addresses"], " ") {
		alreadyBlocked, err := CloudflareBlockIP(ip)
		if err != nil {
			PostMessage(ev.Channel, fmt.Sprintf("@%s Ocorreu um erro ao bloquear os IPs: %s", ev.Username, err.Error()))
			return
		}

		if alreadyBlocked {
			alreadyBlockedIPs = append(alreadyBlockedIPs, ip)
		} else {
			blockedIPs = append(blockedIPs, ip)
		}
	}

	if len(alreadyBlockedIPs) > 0 {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Os seguintes IPs já estavam bloqueados: %s", ev.Username, strings.Join(alreadyBlockedIPs, " ")))
	}

	if len(blockedIPs) > 0 {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Os seguintes IPs foram bloqueados: %s", ev.Username, strings.Join(blockedIPs, " ")))
	}
	return
}

/*
Unblocks the specified IPs on the account's WAF

HandlerName

 waf

RequiredPermission

 waf

Regex

 waf (?P<command>unblock) (?P<addresses>(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}\\s?)+)

 waf (?P<account>\\S+) (?P<region>\\S+) (?P<command>unblock) (?P<addresses>(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}\\s?)+)

Usage

 waf unblock <addresses>

 waf <account> <region> unblock <addresses>
*/
func CFUnblockCommand(md map[string]string, ev *slack.MessageEvent) {
	var unblockedIPs []string
	var notFoundIPs []string

	for _, ip := range strings.Split(md["addresses"], " ") {
		unblocked, err := CloudflareUnblockIP(ip)
		if err != nil {
			PostMessage(ev.Channel, fmt.Sprintf("@%s Ocorreu um erro ao desbloquear os IPs: %s", ev.Username, err.Error()))
			return
		}

		if unblocked {
			unblockedIPs = append(unblockedIPs, ip)
		} else {
			notFoundIPs = append(notFoundIPs, ip)
		}
	}

	if len(notFoundIPs) > 0 {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Os seguintes IPs não foram encontrados: %s", ev.Username, strings.Join(notFoundIPs, " ")))
	}

	if len(unblockedIPs) > 0 {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Os seguintes IPs estavam listados e foram desbloqueados: %s", ev.Username, strings.Join(unblockedIPs, " ")))
	}
	return
}
