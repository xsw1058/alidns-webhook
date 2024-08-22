package alidns

import (
	"fmt"
	dns "github.com/alibabacloud-go/alidns-20150109/v2/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/pkg/errors"
	"log"
)

const recordTypeTxt = "TXT"

type Client struct {
	*dns.Client
}

func NewClient(accessKeyId string, accessKeySecret string, regionId string) (*Client, error) {
	config := &openapi.Config{}
	// 传AccessKey ID入config
	config.AccessKeyId = tea.String(accessKeyId)
	// 传AccessKey Secret入config
	config.AccessKeySecret = tea.String(accessKeySecret)
	config.RegionId = tea.String(regionId)

	client, err := dns.NewClient(config)
	if err != nil {
		return nil, errors.Wrap(err, "init ali dns client failed")
	}
	log.Printf("init ali dns client. accessKeyId: %s, accessKeySecret: %s, regionId: %s \n", accessKeyId, accessKeySecret, regionId)
	return &Client{
		client,
	}, nil
}

func (c *Client) DeleteAndPresent(action, domainName, rr, value string) error {

	result, err := c.DescribeDomainRecords(&dns.DescribeDomainRecordsRequest{
		DomainName:  &domainName,
		RRKeyWord:   &rr,
		TypeKeyWord: tea.String(recordTypeTxt),
	})

	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("DescribeDomainRecords domain(%v) record(%v) failed", domainName, rr))
	}

	for _, v := range result.Body.DomainRecords.Record {
		if *v.DomainName == domainName && *v.RR == rr && *v.Value == value {
			if action == "Present" {
				return nil
			}
			_, err := c.DeleteDomainRecord(&dns.DeleteDomainRecordRequest{
				RecordId: v.RecordId,
			})
			if err != nil {
				return errors.Wrap(err, fmt.Sprintf("DeleteDomainRecord domain(%v) record(%v) failed", domainName, rr))
			}
			log.Printf("delete record. id: %s, domain: %s, rr: %s, value: %s \n",
				*v.RecordId, *v.DomainName, *v.RR, *v.Value)
		}
	}

	if action == "Present" {
		v, err := c.AddDomainRecord(&dns.AddDomainRecordRequest{
			DomainName: &domainName,
			RR:         &rr,
			Type:       tea.String(recordTypeTxt),
			Value:      &value,
		})

		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("AddDomainRecord domain(%v) record(%v) failed", domainName, rr))
		}
		log.Printf("add record. id: %s, domain: %s, rr: %s, value: %s \n",
			*v.Body.RecordId, domainName, rr, value)
	}

	return nil
}
