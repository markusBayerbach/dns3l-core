package clitypes

import (
	"fmt"
	"os"
	"strconv"

	"github.com/dns3l/dns3l-core/dns/types"
	"github.com/spf13/viper"
)

/*DNSAddType ---------------------------------------------------------------------------------
dns:
   add     	Add A, CNAME, TXT, ... to DNS backend
   			Arguments:
  				FQDN: Fully qualified domain name, potential zone nesting is reflected
  				TYPE: A|TXT|CNAME|... Resource record type
  				DATA: IP|STR|NAME IP address, string or canonical name based on TYPE
				SECONDS: UINT, TTL in seconds
			Options:
  				-b, --backend   | Name of the sections in the config.yaml, which contains the configuration for this DNS backend
  				-f, --force     | Change existing DATA
				-i, --id  		| id e.g. username or accesskey depends on the type of the DNS backend
				-s  --secret  	| password or secret depends on the type of the DNS backend
---------------------------------------------------------------------------------------- */
type DNSAddType struct {
	Verbose    bool
	JSONOutput bool
	Provider   string
	Backend    string
	Force      bool
	ID         string
	Secret     string
	UsePWSafe  bool
	FQDN       string
	Type       string
	Data       string
	Seconds    int
	P          types.DNSProvider
}

// Init inits the parameters of the command dns add
func (dnsAdd *DNSAddType) Init(verbose bool, jsonOutput bool, backend string, force bool, id string, secret string, usePWSafe bool, args []string) error {
	dnsAdd.Verbose = verbose
	dnsAdd.JSONOutput = jsonOutput
	dnsAdd.Backend = backend
	dnsAdd.Force = force
	dnsAdd.ID = id
	dnsAdd.Secret = secret
	dnsAdd.UsePWSafe = usePWSafe
	dnsAdd.FQDN = args[0]
	dnsAdd.Type = args[1]
	dnsAdd.Data = args[2]
	if val, err := strconv.Atoi(args[3]); err == nil {
		dnsAdd.Seconds = val
	} else {
		return NewValueError(1302, fmt.Errorf("cmd DNS ADD Argument for TTL is not valid"))
	}
	var err error
	// viper read the config from the requested DNS provider from the yaml file with the help of viper
	dnsAdd.P, err = setProvider(backend, id, secret, usePWSafe, verbose)
	return err
}

// PrintParams prints the parameters of the command dns add
func (dnsAdd *DNSAddType) PrintParams() {
	if dnsAdd.Verbose {
		fmt.Fprintf(os.Stderr, "Command DNS ADD called \n")
		PrintViperConfigDNS()
		fmt.Fprintf(os.Stderr, "JsonOutput 	'%t' \n", dnsAdd.JSONOutput)
		fmt.Fprintf(os.Stderr, "Backend  	'%s' \n", dnsAdd.Backend)
		fmt.Fprintf(os.Stderr, "User 	    '%s' \n", dnsAdd.ID)
		// fmt.Fprintf(os.Stderr, "Password 	'%s' \n", dnsAdd.Secret)
		fmt.Fprintf(os.Stderr, "Password 	'%s' \n", "*****")
		fmt.Fprintf(os.Stderr, "Use password safe	'%v' \n", dnsAdd.UsePWSafe)
		fmt.Fprintf(os.Stderr, "Force         	'%t' \n", dnsAdd.Force)
		fmt.Fprintf(os.Stderr, "dnsFQDN         '%s' Check:= '%t' \n", dnsAdd.FQDN, CheckTypeOfFQDN(dnsAdd.FQDN))
		fmt.Fprintf(os.Stderr, "dnsType         '%s' Check:= '%t'\n", dnsAdd.Type, CheckTypeOfDNSRecord(dnsAdd.Type))
		fmt.Fprintf(os.Stderr, "dnsData         '%s' Check:= '%t'\n", dnsAdd.Data, CheckTypeOfData(dnsAdd.Data, dnsAdd.Type))
		// print params of dns provider
		PrintDNSProvider(dnsAdd.P)
	}
}

// CheckParams prints the parameters of the command dns add
func (dnsAdd *DNSAddType) CheckParams() error {
	// check provider
	// check api
	OK := true
	var errText string
	if !CheckTypeOfFQDN(dnsAdd.FQDN) {
		OK = false
		errText = fmt.Sprintf("command DNS ADD parameter dnsFQDN  '%s' is not valid", dnsAdd.FQDN)
	}
	if !CheckTypeOfDNSRecord(dnsAdd.Type) {
		OK = false
		errText = fmt.Sprintf("command DNS ADD parameter dnsType  '%s'  is not valid", dnsAdd.Type)
	}
	if !CheckTypeOfData(dnsAdd.Data, dnsAdd.Type) {
		OK = false
		errText = fmt.Sprintf("command DNS ADD parameter dnsData  '%s'  is not valid", dnsAdd.Data)
	}
	// dnsAdd.Provider
	vip := viper.GetViper()
	host := vip.GetString("dns.providers." + dnsAdd.Backend + ".host")
	if host == "" {
		errText = fmt.Sprintf("cmd DNS ADD dns provider not in config '%s'", "dns.providers."+dnsAdd.Backend+".host")
		OK = false
	}
	if !OK {
		return NewValueError(1301, fmt.Errorf(errText))
	}
	return nil
}
