/*
 * Copyright 2018 Venafi, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package tpp

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	"net/http"
	"time"
)

// Connector contains the base data needed to communicate with a TPP Server
type Connector struct {
	baseURL string
	apiKey  string
	verbose bool
	trust   *x509.CertPool
	zone    string
}

// NewConnector creates a new TPP Connector object used to communicate with TPP
func NewConnector(verbose bool, trust *x509.CertPool) *Connector {
	c := Connector{trust: trust, verbose: verbose}
	return &c
}

func (c *Connector) SetZone(z string) {
	c.zone = z
}

func (c *Connector) GetType() endpoint.ConnectorType {
	return endpoint.ConnectorTypeTPP
}

//Ping attempts to connect to the TPP Server WebSDK API and returns an errror if it cannot
func (c *Connector) Ping() (err error) {
	statusCode, status, _, err := c.request("GET", "", nil)
	if err != nil {
		return
	}
	if statusCode != http.StatusOK {
		err = fmt.Errorf(status)
	}
	return
}

//Register does nothing for TPP
func (c *Connector) Register(email string) (err error) {
	return nil
}

// Authenticate authenticates the user to the TPP
func (c *Connector) Authenticate(auth *endpoint.Authentication) (err error) {
	if auth == nil {
		return fmt.Errorf("failed to authenticate: missing credentials")
	}
	statusCode, status, body, err := c.request("POST", urlResourceAuthorize, authorizeResquest{Username: auth.User, Password: auth.Password})
	if err != nil {
		return
	}

	key, err := parseAuthorizeResult(statusCode, status, body)
	if err != nil {
		return
	}
	c.apiKey = key
	return
}

func wrapAltNames(req *certificate.Request) (items []sanItem) {
	for _, name := range req.EmailAddresses {
		items = append(items, sanItem{1, name})
	}
	for _, name := range req.DNSNames {
		items = append(items, sanItem{2, name})
	}
	for _, name := range req.IPAddresses {
		items = append(items, sanItem{7, name.String()})
	}
	return items
}

//todo:remove unused
func wrapKeyType(kt certificate.KeyType) string {
	switch kt {
	case certificate.KeyTypeRSA:
		return "RSA"
	case certificate.KeyTypeECDSA:
		return "ECC"
	default:
		return kt.String()
	}
}

func prepareRequest(req *certificate.Request, zone string) (tppReq certificateRequest, err error) {
	switch req.CsrOrigin {
	case certificate.LocalGeneratedCSR, certificate.UserProvidedCSR:
		tppReq = certificateRequest{
			PolicyDN:                getPolicyDN(zone),
			PKCS10:                  string(req.CSR),
			ObjectName:              req.FriendlyName,
			DisableAutomaticRenewal: true}

	case certificate.ServiceGeneratedCSR:
		tppReq = certificateRequest{
			PolicyDN:                getPolicyDN(zone),
			ObjectName:              req.FriendlyName,
			Subject:                 req.Subject.CommonName, // TODO: there is some problem because Subject is not only CN
			SubjectAltNames:         wrapAltNames(req),
			DisableAutomaticRenewal: true}

	default:
		return tppReq, fmt.Errorf("Unexpected option in PrivateKeyOrigin")
	}

	switch req.KeyType {
	case certificate.KeyTypeRSA:
		tppReq.KeyAlgorithm = "RSA"
		tppReq.KeyBitSize = req.KeyLength
	case certificate.KeyTypeECDSA:
		tppReq.KeyAlgorithm = "ECC"
		tppReq.EllipticCurve = req.KeyCurve.String()
	}

	return tppReq, err
}

// RequestCertificate submits the CSR to TPP returning the DN of the requested Certificate
func (c *Connector) RequestCertificate(req *certificate.Request, zone string) (requestID string, err error) {

	if zone == "" {
		zone = c.zone
	}

	tppCertificateRequest, err := prepareRequest(req, zone)
	if err != nil {
		return "", err
	}
	statusCode, status, body, err := c.request("POST", urlResourceCertificateRequest, tppCertificateRequest)
	if err != nil {
		return "", err
	}
	requestID, err = parseRequestResult(statusCode, status, body)
	if err != nil {
		return "", fmt.Errorf("%s: %s", err, string(body)) //todo: remove body from error
	}
	req.PickupID = requestID
	return requestID, nil
}

// RetrieveCertificate attempts to retrieve the requested certificate
func (c *Connector) RetrieveCertificate(req *certificate.Request) (certificates *certificate.PEMCollection, err error) {

	includeChain := req.ChainOption != certificate.ChainOptionIgnore
	rootFirstOrder := includeChain && req.ChainOption == certificate.ChainOptionRootFirst

	if req.PickupID == "" && req.Thumbprint != "" {
		// search cert by Thumbprint and fill pickupID
		searchResult, err := c.searchCertificatesByFingerprint(req.Thumbprint)
		if err != nil {
			return nil, fmt.Errorf("Failed to create renewal request: %s", err)
		}
		if len(searchResult.Certificates) == 0 {
			return nil, fmt.Errorf("No certifiate found using fingerprint %s", req.Thumbprint)
		}
		if len(searchResult.Certificates) > 1 {
			return nil, fmt.Errorf("Error: more than one CertificateRequestId was found with the same thumbprint")
		}
		req.PickupID = searchResult.Certificates[0].CertificateRequestId
	}

	certReq := certificateRetrieveRequest{
		CertificateDN:  req.PickupID,
		Format:         "base64",
		RootFirstOrder: rootFirstOrder,
		IncludeChain:   includeChain,
	}
	if req.CsrOrigin == certificate.ServiceGeneratedCSR || req.FetchPrivateKey {
		certReq.IncludePrivateKey = true
		certReq.Password = req.KeyPassword
	}

	startTime := time.Now()
	for {
		retrieveResponse, err := c.retrieveCertificateOnce(certReq)
		if err != nil {
			return nil, fmt.Errorf("unable to retrieve: %s", err)
		}
		if retrieveResponse.CertificateData != "" {
			return newPEMCollectionFromResponse(retrieveResponse.CertificateData, req.ChainOption)
		}
		if req.Timeout == 0 {
			return nil, endpoint.ErrCertificatePending{CertificateID: req.PickupID, Status: retrieveResponse.Status}
		}
		if time.Now().After(startTime.Add(req.Timeout)) {
			return nil, endpoint.ErrRetrieveCertificateTimeout{CertificateID: req.PickupID}
		}
		time.Sleep(2 * time.Second)
	}
}

func (c *Connector) retrieveCertificateOnce(certReq certificateRetrieveRequest) (*certificateRetrieveResponse, error) {
	statusCode, status, body, err := c.request("POST", urlResourceCertificateRetrieve, certReq)
	if err != nil {
		return nil, err
	}
	retrieveResponse, err := parseRetrieveResult(statusCode, status, body)
	if err != nil {
		return nil, err
	}
	return &retrieveResponse, nil
}

// RenewCertificate attempts to renew the certificate
func (c *Connector) RenewCertificate(renewReq *certificate.RenewalRequest) (requestID string, err error) {

	if renewReq.Thumbprint != "" && renewReq.CertificateDN == "" {
		// search by Thumbprint and fill *renewReq.CertificateDN
		searchResult, err := c.searchCertificatesByFingerprint(renewReq.Thumbprint)
		if err != nil {
			return "", fmt.Errorf("Failed to create renewal request: %s", err)
		}
		if len(searchResult.Certificates) == 0 {
			return "", fmt.Errorf("No certifiate found using fingerprint %s", renewReq.Thumbprint)
		}
		if len(searchResult.Certificates) > 1 {
			return "", fmt.Errorf("Error: more than one CertificateRequestId was found with the same thumbprint")
		}

		renewReq.CertificateDN = searchResult.Certificates[0].CertificateRequestId
	}
	if renewReq.CertificateDN == "" {
		return "", fmt.Errorf("failed to create renewal request: CertificateDN or Thumbprint required")
	}

	var r = certificateRenewRequest{}
	r.CertificateDN = renewReq.CertificateDN
	if renewReq.CertificateRequest != nil && len(renewReq.CertificateRequest.CSR) > 0 {
		r.PKCS10 = string(renewReq.CertificateRequest.CSR)
	}
	statusCode, status, body, err := c.request("POST", urlResourceCertificateRenew, r)
	if err != nil {
		return "", err
	}

	response, err := parseRenewResult(statusCode, status, body)
	if err != nil {
		return "", err
	}
	if !response.Success {
		return "", fmt.Errorf("Certificate Renewal error: %s", response.Error)
	}
	return renewReq.CertificateDN, nil
}

// RevokeCertificate attempts to revoke the certificate
func (c *Connector) RevokeCertificate(revReq *certificate.RevocationRequest) (err error) {
	reason, ok := RevocationReasonsMap[revReq.Reason]
	if !ok {
		return fmt.Errorf("could not parse revocation reason `%s`", revReq.Reason)
	}

	var r = certificateRevokeRequest{
		revReq.CertificateDN,
		revReq.Thumbprint,
		reason,
		revReq.Comments,
		revReq.Disable,
	}
	statusCode, status, body, err := c.request("POST", urlResourceCertificateRevoke, r)
	revokeResponse, err := parseRevokeResult(statusCode, status, body)
	if err != nil {
		return
	}
	if !revokeResponse.Success {
		return fmt.Errorf("Revocation error: %s", revokeResponse.Error)
	}
	return
}

type _strValue struct {
	Locked bool
	Value  string
}

type serverPolicy struct {
	CertificateAuthority _strValue
	CsrGeneration        _strValue
	KeyGeneration        _strValue
	KeyPair              struct {
		KeyAlgorithm _strValue
		KeySize      struct {
			Locked bool
			Value  int
		}
		KeyCurve struct { //todo: check field name
			Locked bool
			Value  string //todo: check field name and type
		}
	}
	ManagementType _strValue

	PrivateKeyReuseAllowed  bool
	SubjAltNameDnsAllowed   bool
	SubjAltNameEmailAllowed bool
	SubjAltNameIpAllowed    bool
	SubjAltNameUpnAllowed   bool
	SubjAltNameUriAllowed   bool
	Subject                 struct {
		City               _strValue
		Country            _strValue
		Organization       _strValue
		OrganizationalUnit struct {
			Locked bool
			Values []string
		}

		State _strValue
	}
	UniqueSubjectEnforced bool
	WhitelistedDomains    []string
	WildcardsAllowed      bool
}

func (sp serverPolicy) toPolicy() (p endpoint.Policy) {
	const allAllowedRegex = ".*"
	if len(sp.WhitelistedDomains) == 0 {
		p.SubjectCNRegexes = []string{allAllowedRegex}
	} else {
		p.SubjectCNRegexes = sp.WhitelistedDomains
	}
	if sp.Subject.OrganizationalUnit.Locked {
		p.SubjectOURegexes = sp.Subject.OrganizationalUnit.Values
	} else {
		p.SubjectOURegexes = []string{allAllowedRegex}
	}
	if sp.Subject.Organization.Locked {
		p.SubjectORegexes = []string{sp.Subject.Organization.Value}
	} else {
		p.SubjectORegexes = []string{allAllowedRegex}
	}
	if sp.Subject.City.Locked {
		p.SubjectLRegexes = []string{sp.Subject.City.Value}
	} else {
		p.SubjectLRegexes = []string{allAllowedRegex}
	}
	if sp.Subject.State.Locked {
		p.SubjectSTRegexes = []string{sp.Subject.State.Value}
	} else {
		p.SubjectSTRegexes = []string{allAllowedRegex}
	}
	if sp.Subject.Country.Locked {
		p.SubjectCRegexes = []string{sp.Subject.Country.Value}
	} else {
		p.SubjectCRegexes = []string{allAllowedRegex}
	}
	if sp.SubjAltNameDnsAllowed {
		p.DnsSanRegExs = make([]string, len(sp.WhitelistedDomains))
		for i, d := range sp.WhitelistedDomains {
			p.DnsSanRegExs[i] = ".*." + d //todo: ask ryan about regexs
		}
	} else {
		p.DnsSanRegExs = []string{}
	}
	if sp.SubjAltNameIpAllowed {
		p.IpSanRegExs = []string{allAllowedRegex}
	} else {
		p.IpSanRegExs = []string{}
	}
	if sp.SubjAltNameEmailAllowed {
		p.EmailSanRegExs = []string{allAllowedRegex}
	} else {
		p.EmailSanRegExs = []string{}
	}
	if sp.SubjAltNameUriAllowed {
		p.UriSanRegExs = []string{allAllowedRegex}
	} else {
		p.UriSanRegExs = []string{}
	}
	if sp.SubjAltNameUpnAllowed {
		p.UpnSanRegExs = []string{allAllowedRegex}
	} else {
		p.UpnSanRegExs = []string{}
	}
	if sp.KeyPair.KeyAlgorithm.Locked {
		var keyType certificate.KeyType
		if err := keyType.Set(sp.KeyPair.KeyAlgorithm.Value); err != nil {
			panic(err)
		}
		key := endpoint.AllowedKeyConfiguration{KeyType: keyType}
		if keyType == certificate.KeyTypeRSA {
			if sp.KeyPair.KeySize.Locked {
				for _, i := range []int{512, 1024, 2048, 4096, 8192} {
					if i > sp.KeyPair.KeySize.Value {
						key.KeySizes = append(key.KeySizes, i)
					}
				}
			} else {
				key.KeySizes = []int{512, 1024, 2048, 4096, 8192}
			}
		} else {
			//todo: check curves
			var curve certificate.EllipticCurve
			if sp.KeyPair.KeyCurve.Locked {
				if err := curve.Set(sp.KeyPair.KeyCurve.Value); err != nil {
					panic(err)
				}
				key.KeyCurves = append(key.KeyCurves, curve)
			} else {
				key.KeyCurves = []certificate.EllipticCurve{
					certificate.EllipticCurveP521,
					certificate.EllipticCurveP224,
					certificate.EllipticCurveP256,
					certificate.EllipticCurveP384,
				}
			}

		}
	}
	p.AllowWildcards = sp.WildcardsAllowed
	p.AllowKeyReuse = sp.PrivateKeyReuseAllowed
	return
}

func (c *Connector) getPolicyConfiguration(zone string) (policy *endpoint.Policy, err error) {
	rq := struct{ PolicyDN string }{getPolicyDN(zone)}
	statusCode, status, body, err := c.request("POST", urlResourceCertificatePolicy, rq)
	if err != nil {
		return
	}
	var r struct {
		Policy serverPolicy
	}
	if statusCode == http.StatusOK {
		err = json.Unmarshal(body, &r.Policy)
		p := r.Policy.toPolicy()
		policy = &p
	} else {
		return nil, fmt.Errorf("Invalid status: %s", status)
	}
	return
}

//ReadZoneConfiguration reads the policy data from TPP to get locked and pre-configured values for certificate requests
func (c *Connector) ReadZoneConfiguration(zone string) (config *endpoint.ZoneConfiguration, err error) {
	zoneConfig := endpoint.NewZoneConfiguration()
	zoneConfig.HashAlgorithm = x509.SHA256WithRSA
	policy, err := c.getPolicyConfiguration(zone)
	if err != nil {
		return
	}
	zoneConfig.Policy = *policy
	return zoneConfig, nil
}

func (c *Connector) ImportCertificate(r *certificate.ImportRequest) (*certificate.ImportResponse, error) {

	if r.PolicyDN == "" {
		r.PolicyDN = getPolicyDN(c.zone)
	}

	statusCode, _, body, err := c.request("POST", urlResourceCertificateImport, r)
	if err != nil {
		return nil, err
	}
	switch statusCode {
	case http.StatusOK:

		var response = &certificate.ImportResponse{}
		err := json.Unmarshal(body, response)
		if err != nil {
			return nil, fmt.Errorf("failed to decode import response message: %s", err)
		}
		return response, nil

	case http.StatusBadRequest:
		var errorResponse = &struct{ Error string }{}
		err := json.Unmarshal(body, errorResponse)
		if err != nil {
			return nil, fmt.Errorf("failed to decode error message: %s", err)
		}
		return nil, fmt.Errorf("%s", errorResponse.Error)
	default:
		return nil, fmt.Errorf("unexpected response status %d: %s", statusCode, string(body))
	}
}
