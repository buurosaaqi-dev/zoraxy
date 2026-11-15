// Package acme handles the acme issuing process
package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/registration"
	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/info/logger"
	"imuslab.com/zoraxy/mod/netutils"
	"imuslab.com/zoraxy/mod/utils"
)

var defaultNameservers = []string{
	"8.8.8.8:53", // Google DNS
	"8.8.4.4:53", // Google DNS
	"1.1.1.1:53", // Cloudflare DNS
	"1.0.0.1:53", // Cloudflare DNS
}

const (
	defaultHTTP01Timeout    = 2 * time.Minute
	maxHTTP01Timeout        = 5 * time.Minute
	minDNS01PropTimeoutSecs = 300
	dns01TimeoutHeadroom    = 2 * time.Minute
	maxDNS01Timeout         = 30 * time.Minute
)

type CertificateInfoJSON struct {
	AcmeName                     string   `json:"acme_name"`                       // ACME provider name
	AcmeUrl                      string   `json:"acme_url"`                        // Custom ACME URL (if any)
	SkipTLS                      bool     `json:"skip_tls"`                        // Skip TLS verification of upstream
	UseDNS                       bool     `json:"dns"`                             // Use DNS challenge
	PropTimeout                  int      `json:"prop_time"`                       // Propagation timeout
	DNSServers                   []string `json:"dnsServers"`                      // DNS servers
	DisableRecursiveNssCheck     bool     `json:"disable_recursive_nss_check"`     // Disable Recursive NSs Propagation Check
	DisableAuthoritativeNssCheck bool     `json:"disable_authoritative_nss_check"` // Disable Authoritative NSs Propagation Check
}

type EABConfig struct {
	Kid     string `json:"kid"`
	HmacKey string `json:"HmacKey"`
}

// ACMEHandler handles ACME-related operations.
type ACMEHandler struct {
	Port           string
	Database       *database.Database
	Logger         *logger.Logger
	TestMode       bool
	KeyFileMode    os.FileMode
	PublicFileMode os.FileMode

	providerOnce sync.Once
	http01       *http01Provider
	accountMu    sync.Mutex
	certLocksMu  sync.Mutex
	certLocks    map[string]*sync.Mutex
}

// NewACME creates a new ACMEHandler instance.
func NewACME(
	port string, database *database.Database,
	logger *logger.Logger, testMode bool, keyFileMode os.FileMode, publicFileMode os.FileMode,
) *ACMEHandler {
	h := &ACMEHandler{
		Port:           port,
		Database:       database,
		Logger:         logger,
		TestMode:       testMode,
		KeyFileMode:    keyFileMode,
		PublicFileMode: publicFileMode,
	}
	h.getHTTP01Provider()
	return h
}

func (a *ACMEHandler) getHTTP01Provider() *http01Provider {
	a.providerOnce.Do(func() {
		a.http01 = newHTTP01Provider(a.Port, a.Logger)
	})
	return a.http01
}

func (a *ACMEHandler) lockCert(certificateName string) func() {
	if certificateName == "" {
		return func() {}
	}
	a.certLocksMu.Lock()
	if a.certLocks == nil {
		a.certLocks = make(map[string]*sync.Mutex)
	}
	mu, ok := a.certLocks[certificateName]
	if !ok {
		mu = &sync.Mutex{}
		a.certLocks[certificateName] = mu
	}
	a.certLocksMu.Unlock()

	mu.Lock()
	return mu.Unlock
}

func certObtainTimeout(useDNS bool, propagationTimeout int, domainCount int) time.Duration {
	if domainCount < 1 {
		domainCount = 1
	}
	if !useDNS {
		timeout := defaultHTTP01Timeout + time.Duration(domainCount-1)*30*time.Second
		if timeout > maxHTTP01Timeout {
			return maxHTTP01Timeout
		}
		return timeout
	}

	propSecs := propagationTimeout
	if propSecs < minDNS01PropTimeoutSecs {
		propSecs = minDNS01PropTimeoutSecs
	}
	timeout := time.Duration(propSecs*domainCount)*time.Second + dns01TimeoutHeadroom
	if timeout > maxDNS01Timeout {
		return maxDNS01Timeout
	}
	return timeout
}

func (a *ACMEHandler) Logf(message string, err error) {
	if a.Logger != nil {
		a.Logger.PrintAndLog("ACME", message, err)
	}
}

// Close shuts down any active HTTP-01 challenge listener managed by this handler.
func (a *ACMEHandler) Close() error {
	if a.http01 != nil {
		return a.http01.Close()
	}
	return nil
}

func (a *ACMEHandler) writeFileWithMode(filename string, data []byte, mode os.FileMode) error {
	err := os.WriteFile(filename, data, mode)
	if err != nil {
		return err
	}

	return os.Chmod(filename, mode)
}

// ObtainCert obtains a certificate for the specified domains.
func (a *ACMEHandler) ObtainCert(domains []string, certificateName string, email string, caName string, caUrl string, skipTLS bool, useDNS bool, propagationTimeout int, dnsServers string, disableRecursiveNssCheck bool, disableAuthoritativeNssCheck bool) (bool, error) {
	return a.ObtainCertContext(context.Background(), domains, certificateName, email, caName, caUrl, skipTLS, useDNS, propagationTimeout, dnsServers, disableRecursiveNssCheck, disableAuthoritativeNssCheck)
}

// ObtainCertContext obtains a certificate for the specified domains under parentCtx.
func (a *ACMEHandler) ObtainCertContext(parentCtx context.Context, domains []string, certificateName string, email string, caName string, caUrl string, skipTLS bool, useDNS bool, propagationTimeout int, dnsServers string, disableRecursiveNssCheck bool, disableAuthoritativeNssCheck bool) (bool, error) {
	if parentCtx == nil {
		parentCtx = context.Background()
	}

	unlockCert := a.lockCert(certificateName)
	defer unlockCert()

	a.Logf("Obtaining certificate for: "+strings.Join(domains, ", "), nil)

	// Resolve the CA directory URL before creating an account or config,
	// so we can check for an existing account before generating a new key.
	//
	// Fallback to Let's Encrypt if it is not set
	if caName == "" {
		caName = "Let's Encrypt"
	}

	// setup the custom ACME url endpoint.
	if caName == "custom" {
		a.Logf("Using Custom ACME "+caUrl+" for CA Directory URL", nil)
	} else if caUrl == "" {
		// if not custom ACME url, load it from ca.json
		caLinkOverwrite, err := loadCAApiServerFromName(caName, a.TestMode)
		if err == nil {
			caUrl = caLinkOverwrite
			a.Logf("Using "+caLinkOverwrite+" for CA Directory URL", nil)
		} else {
			caUrl, _ = loadCAApiServerFromName("Let's Encrypt", a.TestMode)
			a.Logf("Using Default ACME "+caUrl+" for CA Directory URL", nil)
		}
	} else {
		a.Logf("Using "+caUrl+" for CA Directory URL", nil)
	}

	// Load certificate info from JSON file
	certInfo, err := LoadCertInfoJSON(fmt.Sprintf("./conf/certs/%s.json", certificateName))
	if err == nil {
		useDNS = certInfo.UseDNS
		if dnsServers == "" && certInfo.DNSServers != nil && len(certInfo.DNSServers) > 0 {
			dnsServers = strings.Join(certInfo.DNSServers, ",")
		}
		if certInfo.PropTimeout > 0 {
			propagationTimeout = certInfo.PropTimeout
		}
		if certInfo.DisableRecursiveNssCheck {
			disableRecursiveNssCheck = certInfo.DisableRecursiveNssCheck
		}
		if certInfo.DisableAuthoritativeNssCheck {
			disableAuthoritativeNssCheck = certInfo.DisableAuthoritativeNssCheck
		}
	}

	// Ensure at least one NSs propagation check is enabled
	// When disabling authoritative NSs check, recursive NSs check must stay enabled
	if disableAuthoritativeNssCheck && disableRecursiveNssCheck {
		a.Logf("DisableAuthoritativeNssCheck requires recursive NSs check to be enabled; forcing DisableRecursiveNssCheck = false", nil)
		disableRecursiveNssCheck = false
	}

	// Clean DNS servers
	dnsNameservers := strings.Split(dnsServers, ",")
	for i := range dnsNameservers {
		dnsNameservers[i] = strings.TrimSpace(dnsNameservers[i])
	}

	ctx, cancel := context.WithTimeout(parentCtx, certObtainTimeout(useDNS, propagationTimeout, len(domains)))
	defer cancel()

	client, err := a.prepareClientAndAccount(ctx, email, caUrl, skipTLS)
	if err != nil {
		return false, err
	}

	// setup how to receive challenge
	if useDNS {
		if a.Database == nil {
			return false, errors.New("DNS Provider and DNS Credential configuration required for ACME Provider (Error -1)")
		}
		if !a.Database.TableExists("acme") {
			a.Database.NewTable("acme")
			return false, errors.New("DNS Provider and DNS Credential configuration required for ACME Provider (Error -1)")
		}

		if !a.Database.KeyExists("acme", certificateName+"_dns_provider") || !a.Database.KeyExists("acme", certificateName+"_dns_credentials") {
			return false, errors.New("DNS Provider and DNS Credential configuration required for ACME Provider (Error -2)")
		}

		var dnsCredentials string
		err := a.Database.Read("acme", certificateName+"_dns_credentials", &dnsCredentials)
		if err != nil {
			a.Logf("Read DNS credential failed", err)
			return false, err
		}

		var dnsProvider string
		err = a.Database.Read("acme", certificateName+"_dns_provider", &dnsProvider)
		if err != nil {
			a.Logf("Read DNS Provider failed", err)
			return false, err
		}

		provider, err := GetDnsChallengeProviderByName(dnsProvider, dnsCredentials, propagationTimeout)
		if err != nil {
			a.Logf("Unable to resolve DNS challenge provider", err)
			return false, err
		}

		opts := &dns01.Options{}

		if len(dnsNameservers) > 0 && dnsNameservers[0] != "" {
			a.Logf("Using DNS servers: "+strings.Join(dnsNameservers, ", "), nil)
			opts.RecursiveNameservers = dnsNameservers
		} else {
			// Use default DNS-01 nameservers if dnsServers is empty
			opts.RecursiveNameservers = defaultNameservers
		}

		dns01.SetDefaultClient(dns01.NewClient(opts))

		dnsOpts := []dns01.ChallengeOption{}
		if disableRecursiveNssCheck {
			dnsOpts = append(dnsOpts, dns01.DisableRecursiveNSsPropagationRequirement())
		}
		if disableAuthoritativeNssCheck {
			dnsOpts = append(dnsOpts, dns01.DisableAuthoritativeNssPropagationRequirement())
		}
		err = client.Challenge.SetDNS01Provider(provider, dnsOpts...)
		if err != nil {
			a.Logf("Failed to resolve DNS01 Provider", err)
			return false, err
		}
	} else {
		err = client.Challenge.SetHTTP01Provider(a.getHTTP01Provider())
		if err != nil {
			a.Logf("Failed to resolve HTTP01 Provider", err)
			return false, err
		}
	}

	// obtain the certificate
	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
		KeyType: certcrypto.RSA2048,
	}

	certificates, err := client.Certificate.Obtain(ctx, request)
	if err != nil {
		a.Logf("Obtain certificate failed", err)
		return false, err
	}

	// Each certificate comes back with the cert bytes, the bytes of the client's
	// private key, and a certificate URL.
	err = a.writeFileWithMode("./conf/certs/"+certificateName+".pem", certificates.Certificate, a.PublicFileMode)
	if err != nil {
		a.Logf("Failed to write public key to disk", err)
		return false, err
	}
	err = a.writeFileWithMode("./conf/certs/"+certificateName+".key", certificates.PrivateKey, a.KeyFileMode)
	if err != nil {
		a.Logf("Failed to write private key to disk", err)
		return false, err
	}

	// Save certificate's ACME info for renew usage
	certInfo = &CertificateInfoJSON{
		AcmeName:                     caName,
		AcmeUrl:                      caUrl,
		SkipTLS:                      skipTLS,
		UseDNS:                       useDNS,
		PropTimeout:                  propagationTimeout,
		DNSServers:                   dnsNameservers,
		DisableRecursiveNssCheck:     disableRecursiveNssCheck,
		DisableAuthoritativeNssCheck: disableAuthoritativeNssCheck,
	}

	certInfoBytes, err := json.Marshal(certInfo)
	if err != nil {
		a.Logf("Marshal certificate renew config failed", err)
		return false, err
	}

	err = a.writeFileWithMode("./conf/certs/"+certificateName+".json", certInfoBytes, a.PublicFileMode)
	if err != nil {
		a.Logf("Failed to write certificate renew config to file", err)
		return false, err
	}

	return true, nil
}

func (a *ACMEHandler) newLegoConfig(adminUser *ACMEUser, caUrl string, skipTLS bool) *lego.Config {
	config := lego.NewConfig(adminUser)
	config.CADirURL = caUrl

	if skipTLS {
		a.Logf("Ignoring TLS/SSL Verification Error for ACME Server", nil)
		config.HTTPClient.Transport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}
	return config
}

func (a *ACMEHandler) prepareClientAndAccount(ctx context.Context, email string, caUrl string, skipTLS bool) (*lego.Client, error) {
	a.accountMu.Lock()
	if err := ctx.Err(); err != nil {
		a.accountMu.Unlock()
		return nil, err
	}

	if a.Database != nil {
		if loadedKey, loadedReg, ok := a.loadACMEAccount(caUrl, email); ok {
			a.accountMu.Unlock()
			adminUser := ACMEUser{
				Email:        email,
				key:          loadedKey,
				Registration: loadedReg,
			}
			a.Logf("Reusing existing ACME account for "+caUrl, nil)
			return lego.NewClient(a.newLegoConfig(&adminUser, caUrl, skipTLS))
		}
	}
	defer a.accountMu.Unlock()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		a.Logf("Private key generation failed", err)
		return nil, err
	}
	adminUser := ACMEUser{Email: email, key: privateKey}

	config := a.newLegoConfig(&adminUser, caUrl, skipTLS)
	client, err := lego.NewClient(config)
	if err != nil {
		a.Logf("Failed to spawn new ACME client from current config", err)
		return nil, err
	}

	var reg *acme.ExtendedAccount
	if client.GetServerMetadata().ExternalAccountRequired {
		a.Logf("External Account Required for this ACME Provider", nil)
		if a.Database == nil {
			return nil, errors.New("kid and HmacEncoded configuration required for ACME Provider (Error -1)")
		}
		if !a.Database.TableExists("acme") {
			a.Database.NewTable("acme")
			return nil, errors.New("kid and HmacEncoded configuration required for ACME Provider (Error -1)")
		}
		if !a.Database.KeyExists("acme", config.CADirURL+"_kid") || !a.Database.KeyExists("acme", config.CADirURL+"_hmacEncoded") {
			return nil, errors.New("kid and HmacEncoded configuration required for ACME Provider (Error -2)")
		}

		var kid, hmacEncoded string
		if err := a.Database.Read("acme", config.CADirURL+"_kid", &kid); err != nil {
			a.Logf("Failed to read kid from database", err)
			return nil, err
		}
		if err := a.Database.Read("acme", config.CADirURL+"_hmacEncoded", &hmacEncoded); err != nil {
			a.Logf("Failed to read HMAC from database", err)
			return nil, err
		}

		a.Logf("EAB Credential retrieved: "+kid+" / "+hmacEncoded, nil)
		if kid != "" && hmacEncoded != "" {
			reg, err = client.Registration.RegisterWithExternalAccountBinding(ctx, registration.RegisterEABOptions{
				TermsOfServiceAgreed: true,
				Kid:                  kid,
				HmacEncoded:          hmacEncoded,
			})
		}
		if err != nil {
			a.Logf("Register with external account binder failed", err)
			return nil, err
		}
	} else {
		reg, err = client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			a.Logf("Unable to register client", err)
			return nil, err
		}
	}
	adminUser.Registration = reg

	if a.Database != nil && reg != nil {
		if serr := a.saveACMEAccount(config.CADirURL, &adminUser); serr != nil {
			a.Logf("Failed to persist ACME account (may hit account create limits, try a different IP)", serr)
		} else {
			a.Logf("Persisted ACME account for reuse on "+config.CADirURL, nil)
		}
	}

	return client, nil
}

// CheckCertificate returns a list of domains that are in expired certificates.
// It will return all domains that is in expired certificates
// *** if there is a vaild certificate contains the domain and there is a expired certificate contains the same domain
// it will said expired as well!
func (a *ACMEHandler) CheckCertificate() []string {
	// read from dir
	filenames, err := os.ReadDir("./conf/certs/")

	expiredCerts := []string{}

	if err != nil {
		a.Logf("Failed to load certificate folder", err)
		return []string{}
	}

	for _, filename := range filenames {
		certFilepath := filepath.Join("./conf/certs/", filename.Name())

		certBytes, err := os.ReadFile(certFilepath)
		if err != nil {
			// Unable to load this file
			continue
		} else {
			// Cert loaded. Check its expiry time
			block, _ := pem.Decode(certBytes)
			if block != nil {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					elapsed := time.Since(cert.NotAfter)
					if elapsed > 0 {
						// if it is expired then add it in
						// make sure it's uniqueless
						for _, dnsName := range cert.DNSNames {
							if !contains(expiredCerts, dnsName) {
								expiredCerts = append(expiredCerts, dnsName)
							}
						}
						if !contains(expiredCerts, cert.Subject.CommonName) {
							expiredCerts = append(expiredCerts, cert.Subject.CommonName)
						}
					}
				}
			}
		}
	}

	return expiredCerts
}

// Getport returns the current HTTP-01 challenge listener port.
func (a *ACMEHandler) Getport() string {
	return a.getHTTP01Provider().Port()
}

// contains checks if a string is present in a slice.
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

// HandleGetExpiredDomains handles the HTTP GET request to retrieve the list of expired domains.
// It calls the CheckCertificate method to obtain the expired domains and sends a JSON response
// containing the list of expired domains.
func (a *ACMEHandler) HandleGetExpiredDomains(w http.ResponseWriter, r *http.Request) {
	type ExpiredDomains struct {
		Domain []string `json:"domain"`
	}

	info := ExpiredDomains{
		Domain: a.CheckCertificate(),
	}

	js, _ := json.MarshalIndent(info, "", " ")
	utils.SendJSONResponse(w, string(js))
}

// HandleRenewCertificate handles the HTTP GET request to renew a certificate for the provided domains.
// It retrieves the domains and filename parameters from the request, calls the ObtainCert method
// to renew the certificate, and sends a JSON response indicating the result of the renewal process.
func (a *ACMEHandler) HandleRenewCertificate(w http.ResponseWriter, r *http.Request) {
	domainPara, err := utils.PostPara(r, "domains")

	// Clean each domain
	cleanedDomains := []string{}
	if domainPara != "" {
		for _, d := range strings.Split(domainPara, ",") {
			// Apply normalization on each domain
			nd, err := netutils.NormalizeDomain(d)
			if err != nil {
				utils.SendErrorResponse(w, jsonEscape(err.Error()))
				return
			}
			cleanedDomains = append(cleanedDomains, nd)
		}
	}

	if err != nil {
		utils.SendErrorResponse(w, jsonEscape(err.Error()))
		return
	}

	filename, err := utils.PostPara(r, "filename")
	if err != nil {
		utils.SendErrorResponse(w, jsonEscape(err.Error()))
		return
	}
	// Make sure the wildcard * do not goes into the filename
	filename = strings.ReplaceAll(filename, "*", "_")

	email, err := utils.PostPara(r, "email")
	if err != nil {
		utils.SendErrorResponse(w, jsonEscape(err.Error()))
		return
	}

	var caUrl string

	ca, err := utils.PostPara(r, "ca")
	if err != nil {
		a.Logf("CA not set. Using default", nil)
		ca, caUrl = "", ""
	}

	if ca == "custom" {
		caUrl, err = utils.PostPara(r, "caURL")
		if err != nil {
			a.Logf("Custom CA set but no URL provide, Using default", nil)
			ca, caUrl = "", ""
		}
	}

	if ca == "" {
		// default. Use Let's Encrypt
		ca = "Let's Encrypt"
	}

	skipTLS, _ := utils.PostBool(r, "skipTLS")
	dns, _ := utils.PostBool(r, "dns")

	// Default propagation timeout is 600 seconds (10 minutes)
	propagationTimeout := 600
	if dns {
		ppgTimeout, err := utils.PostPara(r, "ppgTimeout")
		if err == nil {
			propagationTimeout, err = strconv.Atoi(ppgTimeout)
			if err != nil {
				utils.SendErrorResponse(w, "Invalid propagation timeout value")
				return
			}
			if propagationTimeout < 60 {
				// Minimum propagation timeout is 60 seconds
				propagationTimeout = 60
			}
		}
	}

	// Extract SANs from existing PEM to ensure all domains are included
	pemPath := fmt.Sprintf("./conf/certs/%s.pem", filename)
	sanDomains, err := ExtractDomainsFromPEM(pemPath)
	if err == nil {
		// Merge domainPara + SANs
		domainSet := map[string]struct{}{}
		for _, d := range cleanedDomains {
			domainSet[d] = struct{}{}
		}
		for _, d := range sanDomains {
			domainSet[d] = struct{}{}
		}

		// Rebuild cleanedDomains with all unique domains
		cleanedDomains = []string{}
		for d := range domainSet {
			cleanedDomains = append(cleanedDomains, d)
		}

		a.Logf("Renewal domains including SANs from PEM: "+strings.Join(cleanedDomains, ","), nil)
	} else {
		a.Logf("Could not extract SANs from PEM, using domainPara only", err)
	}

	// Extract DNS servers from the request
	var dnsServers []string
	dnsServersPara, err := utils.PostPara(r, "dnsServers")
	if err == nil && dnsServersPara != "" {
		dnsServers = strings.Split(dnsServersPara, ",")
		for i := range dnsServers {
			dnsServers[i] = strings.TrimSpace(dnsServers[i])
		}
	}

	// Convert DNS servers slice to a single string
	dnsServersString := strings.Join(dnsServers, ",")

	// PostBool returns false if the key is missing or not a valid bool
	disableRecursiveNssCheck, _ := utils.PostBool(r, "disable_recursive_nss_check")
	disableAuthoritativeNssCheck, _ := utils.PostBool(r, "disable_authoritative_nss_check")

	result, err := a.ObtainCert(cleanedDomains, filename, email, ca, caUrl, skipTLS, dns, propagationTimeout, dnsServersString, disableRecursiveNssCheck, disableAuthoritativeNssCheck)
	if err != nil {
		utils.SendErrorResponse(w, jsonEscape(err.Error()))
		return
	}
	utils.SendJSONResponse(w, strconv.FormatBool(result))
}

// Escape JSON string
func jsonEscape(i string) string {
	b, err := json.Marshal(i)
	if err != nil {
		// log.Println("Unable to escape json data: " + err.Error())
		return i
	}
	s := string(b)
	return s[1 : len(s)-1]
}

// Helper function to check if a port is in use
func IsPortInUse(port int) bool {
	address := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return true // Port is in use
	}
	defer listener.Close()
	return false // Port is not in use
}

// Load cert information from json file
func LoadCertInfoJSON(filename string) (*CertificateInfoJSON, error) {
	certInfoBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	certInfo := &CertificateInfoJSON{}
	if err = json.Unmarshal(certInfoBytes, certInfo); err != nil {
		return nil, err
	}

	// Clean DNS servers
	for i := range certInfo.DNSServers {
		certInfo.DNSServers[i] = strings.TrimSpace(certInfo.DNSServers[i])
	}

	return certInfo, nil
}
