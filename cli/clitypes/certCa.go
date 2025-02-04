package clitypes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

/*
CertCaType ----------------------------------------------------------------------------

	 cert	ca
	 List all certificate authorities (CA) utilized by DNS3L
	 Flags
		-a, --api   	| DNS3L API endpoint [$DNS3L_API]

200 = OK
-----------------------------------------------------------------------------------------
*/
type CertCaType struct {
	Verbose     bool
	JSONOutput  bool
	APIEndPoint string
	CertToken   string
}

type CAInfo struct {
	Id          string   `json:"id"`          // Unique supported CA ID
	Name        string   `json:"name"`        // 	Descriptive CA name
	Desc        string   `json:"desc"`        // 	CA description
	Logo        string   `json:"logo"`        // 	CA avatar URI
	Url         string   `json:"url"`         // 	CA URL
	Roots       string   `json:"roots"`       // 	CA root certificates program URL
	TotalValid  int32    `json:"totalValid"`  // Number of issued valid X.509 certificates
	TotalIssued int32    `json:"totalIssued"` // Total number of issued X.509 certificates
	Type        string   `json:"type"`        // Private or public (CT enforcing) CA Allowed: public┃private
	Acme        bool     `json:"acme"`        // 	ACME capable CA
	Rtzn        []string `json:"rtzn"`        // 	Root domain suffixes CA supports
	Enabled     bool     `json:"enable"`      // 	CA enabled for usage
}

// Init inits the parameters of the command cert ca
func (CertCa *CertCaType) Init(verbose bool, jsonOutput bool, certAPIEndPoint string, CertToken string) {
	CertCa.Verbose = verbose
	CertCa.JSONOutput = jsonOutput
	CertCa.APIEndPoint = certAPIEndPoint
	CertCa.CertToken = CertToken
}

// PrintParams prints the parameters of the command cert ca
func (CertCa *CertCaType) PrintParams() {
	if CertCa.Verbose {
		fmt.Fprintf(os.Stderr, "INFO: Command Cert CA called \n")
		PrintViperConfigCert()
		fmt.Fprintf(os.Stderr, "INFO: JsonOut 	    '%t' \n", CertCa.JSONOutput)
		fmt.Fprintf(os.Stderr, "INFO:Api EndPoint  	'%s' \n", CertCa.APIEndPoint)
		fmt.Fprintf(os.Stderr, "Token  (4 < len)    '%t' \n", (len(CertCa.CertToken) > 4))
	}
}

// CheckParams  checks the parameters of the command cert ca
func (CertCa *CertCaType) CheckParams() error {
	// check CertCA
	var errText string
	OK := true
	if len(CertCa.CertToken) <= 4 {
		errText = "cert ca: Token  heuristic check failed"
		OK = false
	}
	if !OK {
		return NewValueError(10101, fmt.Errorf(errText))
	}
	return nil
}

func (CertCa *CertCaType) DoCommand() error {
	var listCaUrl string
	if CertCa.APIEndPoint[len(CertCa.APIEndPoint)-1] == byte('/') {
		listCaUrl = CertCa.APIEndPoint + "ca"
	} else {
		listCaUrl = CertCa.APIEndPoint + "/ca"
	}
	req, err := http.NewRequest("GET", listCaUrl, nil)
	if err != nil {
		return NewValueError(10401, fmt.Errorf("cert ca:: url='%v' Error'%v'", listCaUrl, err.Error()))
	}
	req.Header.Set("Accept", "application/json")
	// Create a Bearer string by appending string access token
	var bearer = "Bearer " + FinalCertToken(CertCa.CertToken)
	// add authorization header to the req
	req.Header.Add("Authorization", bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return NewValueError(10402, fmt.Errorf("cert ca: Request failed Error:= '%v'", err.Error()))
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return NewValueError(20000+resp.StatusCode, fmt.Errorf("request failed http statuscode:= '%v'", resp.StatusCode))
	}
	if CertCa.Verbose {
		PrintFullRespond("INFO: Command.certCA: Request dump", resp)
	}
	var aCAList []CAInfo
	if err = json.NewDecoder(resp.Body).Decode(&aCAList); err != nil {
		return NewValueError(11403, fmt.Errorf("cert ca: decoding Error '%v' No Data received", err.Error()))
	}
	if CertCa.Verbose {
		fmt.Fprintf(os.Stdout, "%v\n", resp.StatusCode)
	}
	//Json Output
	caListJson, errMarshal := json.MarshalIndent(aCAList, "\t", "\t")
	if errMarshal != nil {
		return NewValueError(1140, fmt.Errorf("cert ca: json marshal fails '%v'", errMarshal.Error()))
	}
	// Screen oder JSON File output
	if CertCa.JSONOutput {
		fmt.Fprintf(os.Stdout, "%v\n", string(caListJson))
	} else {
		fmt.Fprintf(os.Stdout, "%v\n", aCAList)
	}
	return nil
}
