package bogus

import (
	"net"

	dnscommon "github.com/dns3l/dns3l-core/dns/common"
	"github.com/dns3l/dns3l-core/dns/types"
	"github.com/sirupsen/logrus"
)

type DNSProvider struct {
	C *Config `validate:"required"`
}

func (p *DNSProvider) GetInfo() *types.DNSProviderInfo {

	return &types.DNSProviderInfo{
		Name:              p.C.Name,
		Feature:           []string{"A", "TXT"},
		ZoneNesting:       true,
		DefaultAutoDNSTTL: dnscommon.ValidateSetDefaultTTL(p.C.TTL.AutoDNS, 3600),
	}

}

func (p *DNSProvider) GetPrecheckConfig() *types.PrecheckConfig {
	conf := &p.C.PreCheck
	conf.SetDefaults()
	return conf
}

func (s *DNSProvider) SetRecordAcmeChallenge(domainName string, challenge string) error {

	log.WithFields(logrus.Fields{"domainName": domainName, "challenge": challenge}).Debug("Setting bogus ACME challenge record.")

	return nil

}

func (s *DNSProvider) SetRecordA(domainName string, ttl uint32, addr net.IP) error {

	log.WithFields(logrus.Fields{"domainName": domainName, "ttl": ttl, "addr": addr}).Debug("Setting bogus A record.")

	return nil

}

func (s *DNSProvider) SetRecordCName(domainName string, canonical string, ttl uint32) error {

	log.WithFields(logrus.Fields{"domainName": domainName, "canonical": canonical, "ttl": ttl}).Debug("Setting bogus CName record.")

	return nil

}

func (s *DNSProvider) SetRecordPTR(domainName string, ttl uint32, addr net.IP) error {

	log.WithFields(logrus.Fields{"domainName": domainName, "ttl": ttl, "addr": addr}).Debug("Setting bogus PTR record.")

	return nil

}

func (s *DNSProvider) SetZoneAuth(domainName string) error {

	log.WithFields(logrus.Fields{"domainName": domainName}).Debug("Setting bogus ZoneAuth record.")

	return nil

}

func (s *DNSProvider) DeleteRecordAcmeChallenge(domainName string) error {

	log.WithFields(logrus.Fields{"domainName": domainName}).Debug("Deleting bogus ACME challenge record.")

	return nil

}

func (s *DNSProvider) DeleteRecordA(domainName string) error {

	log.WithFields(logrus.Fields{"domainName": domainName}).Debug("Deleting bogus A record.")

	return nil

}

func (s *DNSProvider) DeleteRecordCName(domainName string) error {

	log.WithFields(logrus.Fields{"domainName": domainName}).Debug("Deleting bogus CName record.")

	return nil

}

func (s *DNSProvider) DeleteRecordPTR(domainName string) error {

	log.WithFields(logrus.Fields{"domainName": domainName}).Debug("Deleting bogus PTR record.")

	return nil

}
