package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"imuslab.com/zoraxy/mod/acme"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	acme.go

	This script handle special routing required for acme auto cert renew functions
*/

// acmeTokenRegex validates ACME HTTP-01 challenge tokens (RFC 8555).
// Token format: base64url encoded, characters [A-Za-z0-9_-].
var acmeTokenRegex = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

var (
	acmeHTTP01ToggleMu        sync.Mutex
	acmeHTTP01ToggleRefs      int
	acmeHTTP01RestorePort80   bool
	acmeHTTP01RestoreRedirect bool
)

// Helper function to generate a random port above a specified value
func getRandomPort(minPort int) int {
	return rand.Intn(65535-minPort) + minPort
}

// init the new ACME instance
func initACME() *acme.ACMEHandler {
	SystemWideLogger.Println("Starting ACME handler")
	rand.Seed(time.Now().UnixNano())
	// Generate a random port above 30000
	port := getRandomPort(30000)

	// Check if the port is already in use
	for acme.IsPortInUse(port) {
		port = getRandomPort(30000)
	}

	keyFileMode := parseACMEFileMode(*acmeKeyFileMode, 0o600, "acmekeymode")
	publicFileMode := parseACMEFileMode(*acmePublicFileMode, 0o644, "acmepublicmode")

	return acme.NewACME(strconv.Itoa(port), sysdb, SystemWideLogger, *acmeTestMode, keyFileMode, publicFileMode)
}

func parseACMEFileMode(raw string, fallback os.FileMode, flagName string) os.FileMode {
	parsed, err := strconv.ParseUint(raw, 8, 32)
	if err != nil {
		SystemWideLogger.Println("Invalid " + flagName + " value " + raw + ", using fallback " + fmt.Sprintf("%#o", fallback))
		return fallback
	}

	return os.FileMode(parsed)
}

// Restart ACME handler and auto renewer
func restartACMEHandler() {
	SystemWideLogger.Println("Restarting ACME handler")
	// Close the current handler and auto renewer
	acmeHandler.Close()
	acmeAutoRenewer.Close()
	acmeDeregisterSpecialRoutingRule()

	// Reinit the handler with a new random port
	acmeHandler = initACME()

	acmeRegisterSpecialRoutingRule()
}

// create the special routing rule for ACME
func acmeRegisterSpecialRoutingRule() {
	SystemWideLogger.Println("Assigned temporary port:" + acmeHandler.Getport())

	err := dynamicProxyRouter.AddRoutingRules(&dynamicproxy.RoutingRule{
		ID: "acme-autorenew",
		MatchRule: func(r *http.Request) bool {
			// Use ParseRequestURI for strict RFC 3986 validation.
			parsedURL, err := url.ParseRequestURI(r.RequestURI)
			if err != nil {
				return false
			}
			return strings.HasPrefix(parsedURL.Path, "/.well-known/acme-challenge/")
		},
		RoutingHandler: func(w http.ResponseWriter, r *http.Request) {
			parsedURL, err := url.ParseRequestURI(r.RequestURI)
			if err != nil {
				http.Error(w, "Invalid request URI", http.StatusBadRequest)
				return
			}

			// HTTP-01 challenges (RFC 8555) use only the path, no query string.
			// Reject requests with query parameters as they are unexpected.
			if parsedURL.RawQuery != "" {
				http.Error(w, "Query string not allowed in ACME challenge", http.StatusBadRequest)
				return
			}

			// Whitelist: RFC 8555 token is base64url encoded [A-Za-z0-9_-].
			// Extract and validate the token part after the fixed prefix.
			prefix := "/.well-known/acme-challenge/"
			token := strings.TrimPrefix(parsedURL.Path, prefix)
			if len(token) == 0 || len(token) > 255 || !acmeTokenRegex.MatchString(token) {
				http.Error(w, "Invalid ACME challenge token", http.StatusBadRequest)
				return
			}

			// Build internal URL using only the validated path component,
			// preventing SSRF via userinfo injection in the raw URI.
			internalURL := "http://localhost:" + acmeHandler.Getport() + parsedURL.Path

			req, err := http.NewRequest(http.MethodGet, internalURL, nil)
			if err != nil {
				fmt.Printf("client: could not create request: %s\n", err)
				return
			}
			req.Host = r.Host

			res, err := http.DefaultClient.Do(req)
			if err != nil {
				fmt.Printf("client: error making http request: %s\n", err)
				return
			}
			defer res.Body.Close()

			resBody, err := io.ReadAll(res.Body)
			if err != nil {
				fmt.Printf("error reading: %s\n", err)
				return
			}
			w.Write(resBody)
		},
		Enabled:                true,
		UseSystemAccessControl: false,
	})
	if err != nil {
		SystemWideLogger.PrintAndLog("ACME", "Unable register temp port for DNS resolver", err)
	}
}

// remove the special routing rule for ACME
func acmeDeregisterSpecialRoutingRule() {
	SystemWideLogger.Println("Removing ACME routing rule")
	dynamicProxyRouter.RemoveRoutingRule("acme-autorenew")
}

func acquireHTTP01Listeners() (bool, error) {
	acmeHTTP01ToggleMu.Lock()
	defer acmeHTTP01ToggleMu.Unlock()

	if acmeHTTP01ToggleRefs == 0 {
		switch dynamicProxyRouter.Option.Port {
		case 443:
			if !dynamicProxyRouter.Option.ListenOnPort80 {
				SystemWideLogger.PrintAndLog("ACME", "Temporarily enabling port 80 listener to handle ACME request ", nil)
				dynamicProxyRouter.UpdatePort80ListenerState(true)
				acmeHTTP01RestorePort80 = true
			}
			if !dynamicProxyRouter.Option.ForceHttpsRedirect {
				SystemWideLogger.Println("Temporary enabling HTTP to HTTPS redirect for ACME certificate renew requests")
				dynamicProxyRouter.UpdateHttpToHttpsRedirectSetting(true)
				acmeHTTP01RestoreRedirect = true
			}
		case 80:
			// Already listening on port 80.
		default:
			return false, errors.New("ACME renew only support web server listening on port 80 (http) or 443 (https)")
		}
	}

	acmeHTTP01ToggleRefs++
	return acmeHTTP01ToggleRefs == 1 && acmeHTTP01RestorePort80, nil
}

func releaseHTTP01Listeners() {
	acmeHTTP01ToggleMu.Lock()
	defer acmeHTTP01ToggleMu.Unlock()

	if acmeHTTP01ToggleRefs <= 0 {
		return
	}
	acmeHTTP01ToggleRefs--
	if acmeHTTP01ToggleRefs > 0 {
		return
	}

	if acmeHTTP01RestorePort80 {
		SystemWideLogger.PrintAndLog("ACME", "Restoring previous port 80 listener settings", nil)
		dynamicProxyRouter.UpdatePort80ListenerState(false)
		acmeHTTP01RestorePort80 = false
	}
	if acmeHTTP01RestoreRedirect {
		SystemWideLogger.PrintAndLog("ACME", "Restoring HTTP to HTTPS redirect settings", nil)
		dynamicProxyRouter.UpdateHttpToHttpsRedirectSetting(false)
		acmeHTTP01RestoreRedirect = false
	}
}

// This function check if the renew setup is satisfied. If not, toggle them automatically
func AcmeCheckAndHandleRenewCertificate(w http.ResponseWriter, r *http.Request) {
	dnsPara, _ := utils.PostBool(r, "dns")
	if !dnsPara {
		port80Changed, err := acquireHTTP01Listeners()
		if err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
		defer releaseHTTP01Listeners()
		if port80Changed {
			time.Sleep(2 * time.Second)
		}
	}

	// Add a 2 second delay to make sure everything is settle down
	time.Sleep(2 * time.Second)

	// Pass over to the acmeHandler to deal with the communication
	acmeHandler.HandleRenewCertificate(w, r)

	// Update the TLS cert store buffer
	tlsCertManager.UpdateLoadedCertList()
}

// HandleACMEPreferredCA return the user preferred / default CA for new subdomain auto creation
func HandleACMEPreferredCA(w http.ResponseWriter, r *http.Request) {
	type PreferredCA struct {
		Name    string `json:"name"`
		URL     string `json:"url"`
		SkipTLS bool   `json:"skipTLS"`
	}

	ca, err := utils.PostPara(r, "set")
	if err != nil {
		// Return the current ca to user
		prefCA := "Let's Encrypt"
		prefCAURL := ""
		skipTLS := false
		sysdb.Read("acmepref", "prefca", &prefCA)
		sysdb.Read("acmepref", "prefcaurl", &prefCAURL)
		sysdb.Read("acmepref", "skipTLS", &skipTLS)
		js, _ := json.Marshal(PreferredCA{
			Name:    prefCA,
			URL:     prefCAURL,
			SkipTLS: skipTLS,
		})
		utils.SendJSONResponse(w, string(js))
	} else {
		// Check if the CA is supported
		isSupported := acme.IsSupportedCA(ca, *acmeTestMode)

		if !isSupported && ca != "custom" {
			utils.SendErrorResponse(w, "The specified ACME CA is not supported")
			return
		}

		if ca == "custom" {
			customCAURL, err := utils.PostPara(r, "customURL")
			customCAURL = strings.TrimSpace(customCAURL)
			parsedURL, err2 := url.Parse(customCAURL)
			skipTLS, _ := utils.PostBool(r, "skipTLS")

			if err != nil || err2 != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
				utils.SendErrorResponse(w, "Invalid custom CA URL provided")
				return
			}
			sysdb.Write("acmepref", "prefcaurl", customCAURL)
			SystemWideLogger.Println("Updating prefered ACME CA URL to " + customCAURL)
			sysdb.Write("acmepref", "skipTLS", skipTLS)
			SystemWideLogger.Println("Updating prefered skipTLS to " + fmt.Sprintf("%t", skipTLS))
		}
		// Set the new config
		sysdb.Write("acmepref", "prefca", ca)
		SystemWideLogger.Println("Updating prefered ACME CA to " + ca)
		utils.SendOK(w)
	}
}
