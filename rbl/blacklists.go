package rbl

/*
	Work In Progress
*/

// RBL defines the structure of a real-time blocklist (RBL).
type RBL struct {
	Name               string
	URL                string
	Quota              int
	Whitelist          bool
	Paywall            bool
	AccountRequired    bool
	IPv4               bool
	IPv6               bool
	Domain             bool
	Confidence         int
	Quality            int
	Lists              []list
	ReturnCodes        []string
	ReturnCodesDetails map[int]string
}

type list struct {
	Address string
	Details string
	Type    ListType
}

var retrieveRBLFn = map[string]func() *RBL{
	"0spam.org": zeroSpamOrg,
}

func zeroSpamOrg() *RBL {
	r := &RBL{
		Name:            "The 0spam Project",
		URL:             "https://0spam.org",
		Quota:           1000,
		Paywall:         false,
		AccountRequired: true,
		Confidence:      30,
		Quality:         30,
		Whitelist:       true,
		IPv4:            true,
		IPv6:            false,
		Domain:          true,
		ReturnCodes: []string{
			"127.0.0.?",
			"127.0.?.0",
		},
		ReturnCodesDetails: map[int]string{
			1: "General spam, Sending spam to our spam traps.",
			2: "Removal request made but missing required information, please make a new request and be sure to complete the form properly.",
			3: "Does not follow valid can-spam rules for newsletters / lists.",
			4: "Not RFC compliant, server errors or improper configuration.",
			5: "Repeat offenders, these are IP's that have been removed and listed again (3) or more times in a short period of time.",
			6: "Bouncing email to the wrong server, NON RFC compliant configurations.",
			7: "Relay or Open relay with reports of spam.",
			8: "Bouncing spoofed emails, you need to disable bounce of spoofed emails in order to get de listed.",
			9: "Fraud/Scam emails, malware or illegal/abusive content.",
		},
		Lists: []list{
			{
				Address: "bl.0spam.org",
				Details: "DNSBL | 0spam Spam Trap Primary Database",
				Type:    typeIPv4,
			},
			{
				Address: "nbl.0spam.org",
				Details: "Network Black list | Spam Source Networks, high volume of spam trap hits in a Class C block will result in network listings in this DNSBL.",
				Type:    typeIPv4,
			},
			{
				Address: "url.0spam.org",
				Details: "URL Black list | This list contains the IP address of domains found to be in the source of spam emails found in our traps.",
				Type:    typeDomain,
			},
		},
	}

	return r
}
