package pkcs7

import "encoding/asn1"

type RevocationInfoArchival struct {
	Crl          []asn1.RawValue `asn1:"explicit,tag:0,optional"`
	Ocsp         []asn1.RawValue `asn1:"explicit,tag:1,optional"`
	OtherRevInfo []asn1.RawValue `asn1:"explicit,tag:2,optional"`
}
