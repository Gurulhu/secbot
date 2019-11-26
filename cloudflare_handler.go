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
		Handler:            WAFBlockCommand,
		RequiredPermission: "cf",
		HandlerName:        "cf",
		Parameters: map[string]string{
			"addresses": "(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}\\s?)+)",
		}})

	AddCommand(Command{
		Regex:              regexp.MustCompile("cf (?P<command>unblock) (?P<addresses>(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}\\s?)+)"),
		Help:               "Desbloqueia IPs no WAF",
		Usage:              "cf unblock <addresses>",
		Handler:            WAFUnblockCommand,
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

func WAFListCommand(md map[string]string, ev *slack.MessageEvent) {

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
func WAFBlockCommand(md map[string]string, ev *slack.MessageEvent) {
	ips, error := CloudflareListBlockedIPs()

	var existingIPs []string
	var nonExistingIps []string
	for _, v := range strings.Split(md["addresses"], " ") {
		if !stringInSlice(v, ips) {
			var ip = v

			existingIP, err := CloudflareBlockIP(v)
			if err != nil {
				PostMessage(ev.Channel, fmt.Sprintf("@%s Ocorreu um erro ao bloquear os IPs: %s", ev.Username, err.Error()))
				return
			}

			if existingIP {
				existingIPs = append(existingIPs, ip)
			} else {
				nonExistingIps = append(nonExistingIps, ip)
			}
		}
	}

	if len(existingIPs) == 0 {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Todos os IPs listados já se encontram bloqueados", ev.Username))
		return
	}

	PostMessage(ev.Channel, fmt.Sprintf("@%s Os seguintes IPs não estavam listados e foram bloqueados: %s", ev.Username, strings.Join(nonExistingIps, " ")))
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
func WAFUnblockCommand(md map[string]string, ev *slack.MessageEvent) {
	ips, error := CloudflareListBlockedIPs()

	var existingIPs []string
	var nonExistingIps []string
	for _, v := range strings.Split(md["addresses"], " ") {
		if !stringInSlice(v, ips) {
			var ip = v

			existingIP, err := CloudflareUnblockIP(v)
			if err != nil {
				PostMessage(ev.Channel, fmt.Sprintf("@%s Ocorreu um erro ao bloquear os IPs: %s", ev.Username, err.Error()))
				return
			}

			if existingIP {
				existingIPs = append(existingIPs, ip)
			} else {
				nonExistingIps = append(nonExistingIps, ip)
			}
		}
	}

	if len(nonExistingIps) == 0 {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Nenhum dos IPs listados se encontram bloqueados", ev.Username))
		return
	}

	PostMessage(ev.Channel, fmt.Sprintf("@%s Os seguintes IPs estavam listados e foram desbloqueados: %s", ev.Username, strings.Join(existingIPs, " ")))
}
