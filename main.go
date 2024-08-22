package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/pkg/errors"
	"github.com/xsw1058/alidns-webhook/alidns"
	"k8s.io/client-go/kubernetes"
	"log"
	"os"
	"strings"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&aliDNSProviderSolver{},
	)
}

// aliDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type aliDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	k8s          *kubernetes.Clientset
	aliDNSClient *alidns.Client
}

// aliDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type aliDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	//Email           string `json:"email"`
	//APIKeySecretRef v1alpha1.SecretKeySelector `json:"apiKeySecretRef"`
	Region             string                     `json:"region"`
	AccessKeySecretRef cmmetav1.SecretKeySelector `json:"accessKeySecretRef"`
	SecretKeySecretRef cmmetav1.SecretKeySelector `json:"secretKeySecretRef"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *aliDNSProviderSolver) Name() string {
	return "alidns"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *aliDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	log.Println("present", ch.ResolvedFQDN, ch.ResolvedZone)
	client, err := c.initDNSClient(ch)
	if err != nil {
		return fmt.Errorf("error initializing DNS client: %v", err)
	}
	c.aliDNSClient = client

	//{
	//"uid":"",
	//"action":"Present",
	//"type":"dns-01",
	//"dnsName":"xusw2.epartical.com",
	//"key":"43LQz5luSneYdqtX8Pa-BRMt9z13XuLW1QWcwzGeibU",
	//"resourceNamespace":"cert-manager",
	//"resolvedFQDN":"_acme-challenge.xusw2.epartical.com.",
	//"resolvedZone":"epartical.com.",
	//"allowAmbientCredentials":true,
	//"config":{
	//	"accessTokenSecretRef":{"key":"access-token","name":"alidns-secrets"},
	//	"regionId":"",
	//	"secretKeySecretRef":{"key":"secret-key","name":"alidns-secrets"}}
	//}
	unFqdn := util.UnFqdn(ch.ResolvedZone)
	rr := extractRR(ch.ResolvedFQDN, unFqdn)
	return c.aliDNSClient.DeleteAndPresent(string(ch.Action), unFqdn, rr, ch.Key)

}

func (c *aliDNSProviderSolver) initDNSClient(ch *v1alpha1.ChallengeRequest) (*alidns.Client, error) {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, fmt.Errorf("error loading config: %v", err)
	}

	log.Printf("Decoded configuration %s\n", cfg)

	accessToken, err := c.loadSecretData(cfg.AccessKeySecretRef, ch.ResourceNamespace)
	if err != nil {
		return nil, fmt.Errorf("error loading access token: %v", err)
	}

	secretKey, err := c.loadSecretData(cfg.SecretKeySecretRef, ch.ResourceNamespace)
	if err != nil {
		return nil, fmt.Errorf("error loading secret key: %v", err)
	}

	return alidns.NewClient(string(accessToken), string(secretKey), cfg.Region)
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *aliDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	log.Println("cleaning up", ch.ResolvedFQDN)
	client, err := c.initDNSClient(ch)
	if err != nil {
		return errors.Wrap(err, "error initializing DNS client")
	}
	c.aliDNSClient = client
	unFqdn := util.UnFqdn(ch.ResolvedZone)
	rr := extractRR(ch.ResolvedFQDN, unFqdn)
	err = c.aliDNSClient.DeleteAndPresent(string(ch.Action), unFqdn, rr, ch.Key)

	if err != nil {
		return errors.Wrap(err, "error deleting record")
	}
	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *aliDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	///// UNCOMMENT THE BELOW CODE TO MAKE A KUBERNETES CLIENTSET AVAILABLE TO
	///// YOUR CUSTOM DNS PROVIDER
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return errors.Wrap(err, "error creating kubernetes client")
	}

	c.k8s = cl

	///// END OF CODE TO MAKE KUBERNETES CLIENTSET AVAILABLE
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (aliDNSProviderConfig, error) {
	cfg := aliDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (c *aliDNSProviderSolver) loadSecretData(selector cmmetav1.SecretKeySelector, ns string) ([]byte, error) {
	secret, err := c.k8s.CoreV1().Secrets(ns).Get(context.Background(), selector.Name, metav1.GetOptions{})

	if err != nil {
		return nil, errors.Errorf("error getting ns: %v secret <%s>: %v", ns, selector.Name, err)
	}

	if data, ok := secret.Data[selector.Key]; ok {
		return data, nil
	}

	return nil, errors.Errorf("no key %q in secret %q", selector.Key, ns+"/"+selector.Name)
}

func extractRR(fqdn, domain string) string {
	name := util.UnFqdn(fqdn)
	if idx := strings.Index(name, "."+domain); idx != -1 {
		return name[:idx]
	}

	return name
}
