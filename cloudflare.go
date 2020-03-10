package secbot

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/awnumar/memguard"
	"github.com/cloudflare/cloudflare-go"
)

const secbotRefTag = "managed-by-secbot"
const secbotDescriptionTag = "Managed by Secbot"

var zoneID, _ = memguard.NewImmutableFromBytes([]byte(os.Getenv("CLOUDFLARE_ZONE_ID")))
var apiKey, _ = memguard.NewImmutableFromBytes([]byte(os.Getenv("CLOUDFLARE_API_KEY")))
var apiEmail, _ = memguard.NewImmutableFromBytes([]byte(os.Getenv("CLOUDFLARE_API_EMAIL")))

/*
api - return the client to connect to Cloudflare
*/
func apiCloudflare() (*cloudflare.API, error) {
	if zoneID == nil || apiKey == nil || apiEmail == nil {
		err := fmt.Errorf("error loading Cloudflare credentials")
		return nil, err
	}

	api, err := cloudflare.New(
		string(apiKey.Buffer()),
		string(apiEmail.Buffer()),
	)

	if err != nil {
		return nil, err
	}

	return api, nil
}

/*
createOrUpdateFilter - create or update an existing filter into Cloudflare API
*/
func createOrUpdateFilter(filter cloudflare.Filter) (*string, error) {
	cf, err := apiCloudflare()
	if err != nil {
		return nil, err
	}

	f := []cloudflare.Filter{}

	if filter.ID == "" {
		f, err = cf.CreateFilters(string(zoneID.Buffer()), []cloudflare.Filter{filter})
		if err != nil {
			return nil, err
		}
	} else {
		var res cloudflare.Filter
		res, err = cf.UpdateFilter(string(zoneID.Buffer()), filter)
		if err != nil {
			return nil, err
		}

		f = append(f, res)
	}

	if err != nil {
		log.Fatal(err)
	}

	return &f[0].ID, nil
}

/*
getFilter - retrieve the filter from the Cloudflare API
*/
func getFilter() (*cloudflare.Filter, error) {
	cf, err := apiCloudflare()
	if err != nil {
		return nil, err
	}

	filters, err := cf.Filters(string(zoneID.Buffer()), cloudflare.PaginationOptions{})
	if err != nil {
		return nil, err
	}

	var filter cloudflare.Filter
	for _, element := range filters {
		if element.Ref == secbotRefTag {
			filter = element
			break
		}
	}

	return &filter, nil
}

/*
createOrUpdateFirewallRule - create or update an existing firewall rule into Cloudflare API
*/
func createOrUpdateFirewallRule(rule cloudflare.FirewallRule) error {
	cf, err := apiCloudflare()
	if err != nil {
		return err
	}

	if rule.ID == "" {
		_, err = cf.CreateFirewallRules(string(zoneID.Buffer()), []cloudflare.FirewallRule{rule})

	} else {
		_, err = cf.UpdateFirewallRule(string(zoneID.Buffer()), rule)
	}

	return err
}

/*
getFirewallRule - retrieve the firewall rule from the Cloudflare API
*/
func getFirewallRule() (*cloudflare.FirewallRule, error) {
	cf, err := apiCloudflare()
	if err != nil {
		return nil, err
	}

	rules, err := cf.FirewallRules(string(zoneID.Buffer()), cloudflare.PaginationOptions{})
	if err != nil {
		log.Fatal(err)
	}

	var rule cloudflare.FirewallRule
	for _, element := range rules {
		if (element.Filter != cloudflare.Filter{}) && (element.Filter.Ref == secbotRefTag) {
			rule = element
			break
		}
	}

	return &rule, nil
}

/*
getCurrentFilter - retrieve the filter used by Secbot from the Cloudflare API
*/
func getCurrentFilter() (*cloudflare.Filter, error) {
	filter, err := getFilter()
	if err != nil {
		return nil, err
	}

	// if a filter wasn't found, it will
	// instantiate a new object with default configs
	if (cloudflare.Filter{}) == *filter {
		defaultFilter := cloudflare.Filter{
			Description: secbotDescriptionTag,
			Paused:      false,
			Ref:         secbotRefTag,
		}

		return &defaultFilter, nil
	}

	return filter, nil
}

/*
getCurrentFirewallRule - retrieve the firewall rule used by Secbot from the Cloudflare API
*/
func getCurrentFirewallRule() (*cloudflare.FirewallRule, error) {
	rule, err := getFirewallRule()
	if err != nil {
		return nil, err
	}

	// if a firewall rule wasn't found, it will
	// instantiate a new object with default configs
	if (cloudflare.FirewallRule{}) == *rule {
		defaultRule := cloudflare.FirewallRule{
			Action:      "block",
			Description: secbotDescriptionTag,
			Paused:      false,
		}

		return &defaultRule, nil
	}

	return rule, nil
}

/*
extractIPs - extract IPs from a given source
*/
func extractIPs(source string) []string {
	regexIP := regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{2}|)`)
	return regexIP.FindAllString(source, -1)
}

/*
addIP - merges a source containing ips with the new ip informed
*/
func addIP(source string, newIP string) ([]string, bool) {
	existingIP := false
	ips := extractIPs(source)

	// check if IP exists
	for _, value := range ips {
		if value == newIP {
			existingIP = true
			break
		}
	}

	ips = append(ips, newIP)

	// remove possible IPs duplicates
	keys := make(map[string]bool)
	result := []string{}
	for _, ip := range ips {
		if _, value := keys[ip]; !value {
			keys[ip] = true
			result = append(result, ip)
		}
	}

	return result, existingIP
}

/*
removeIP - remove an ip from a given source
*/
func removeIP(source string, ip string) ([]string, bool) {
	ips := extractIPs(source)
	ipRemoved := false

	for i, value := range ips {
		if value == ip {
			ipRemoved = true
			ips = append(ips[:i], ips[i+1:]...)
			break
		}
	}

	return ips, ipRemoved
}

/*
sanitizeIP - return a sanitized IP with CIDR /32
*/
func sanitizeIP(ip string) string {
	var regexIP = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
	result := regexIP.FindString(ip)
	if !regexIP.MatchString(result) {
		log.Fatal("Invalid IP")
	}
	return result + "/32"
}

/*
updateExpression - update a filter with the IP
*/
func updateExpression(filter *cloudflare.Filter, ip string, removalOperation bool) bool {
	const filterTemplate = "ip.src in {%s}"
	var expression string
	existingIP := false

	if filter.ID == "" {
		expression = fmt.Sprintf(filterTemplate, ip)
	} else {
		var ips []string

		if removalOperation {
			ips, existingIP = removeIP(filter.Expression, ip)
		} else {
			ips, existingIP = addIP(filter.Expression, ip)
		}

		expression = fmt.Sprintf(filterTemplate, strings.Join(ips, " "))
	}

	filter.Expression = expression
	return existingIP
}

/*
updateBlacklist - update Cloudflare blacklist
*/
func updateBlacklist(ip string, removalOperation bool) (bool, error) {
	ip = sanitizeIP(ip)
	filter, err := getCurrentFilter()
	if err != nil {
		return false, err
	}

	rule, err := getCurrentFirewallRule()
	if err != nil {
		return false, err
	}

	existingIP := updateExpression(filter, ip, removalOperation)
	id, err := createOrUpdateFilter(*filter)
	if err != nil {
		return false, err
	}

	filter.ID = *id
	rule.Filter = *filter
	err = createOrUpdateFirewallRule(*rule)
	if err != nil {
		return existingIP, err
	}

	return existingIP, nil
}

/*
CloudflareBlockIP - add a IP to blacklist
*/
func CloudflareBlockIP(ip string) (bool, error) {
	return updateBlacklist(ip, false)
}

/*
CloudflareUnblockIP - remove a IP from blacklist
*/
func CloudflareUnblockIP(ip string) (bool, error) {
	return updateBlacklist(ip, true)
}

/*
CloudflareListBlockedIPs - list IPs on blacklist
*/
func CloudflareListBlockedIPs() ([]string, error) {
	filter, err := getCurrentFilter()
	if err != nil {
		return nil, err
	}

	ips := extractIPs(filter.Expression)
	return ips, nil
}
