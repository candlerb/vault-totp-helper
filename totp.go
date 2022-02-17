package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/hashicorp/errwrap"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	multierror "github.com/hashicorp/go-multierror"
	rootcerts "github.com/hashicorp/go-rootcerts"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
	"github.com/hashicorp/vault/sdk/helper/hclutil"
	"github.com/mitchellh/mapstructure"
)

const (
	// TOTPDefaultMountPoint is the default path at which TOTP backend will be
	// mounted in the Vault server.
	TOTPDefaultMountPoint = "totp"
)

// TOTP is a structure representing a vault-totp-helper which can talk to vault server
// in order to verify the OTP entered by the user. It contains the path at which
// TOTP backend is mounted at the server.
type TOTP struct {
	client     *api.Client
	MountPoint string
}

// SSHVerifyResponse is a structure representing the fields in Vault server's
// response.
type TOTPVerifyResponse struct {
	// Whether the response validated succssfully
	Valid bool `json:"valid" mapstructure:"valid"`
}

// TOTPConfig is a structure which represents the entries from the vault-totp-helper's configuration file.
type TOTPConfig struct {
	VaultAddr      string `hcl:"vault_addr"`
	TOTPMountPoint string `hcl:"totp_mount_point"`
	Namespace      string `hcl:"namespace"`
	CACert         string `hcl:"ca_cert"`
	CAPath         string `hcl:"ca_path"`
	TLSSkipVerify  bool   `hcl:"tls_skip_verify"`
	TLSServerName  string `hcl:"tls_server_name"`
	TokenFile      string `hcl:"token_file"`
	RoleID         string `hcl:"role_id"`
	SecretID       string `hcl:"secret_id"`
	SecretFile     string `hcl:"secret_file"`
	SecretEnv      string `hcl:"secret_env"`
}

// SetTLSParameters sets the TLS parameters for this TOTP agent.
func (c *TOTPConfig) SetTLSParameters(clientConfig *api.Config, certPool *x509.CertPool) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.TLSSkipVerify,
		MinVersion:         tls.VersionTLS12,
		RootCAs:            certPool,
		ServerName:         c.TLSServerName,
	}

	transport := cleanhttp.DefaultTransport()
	transport.TLSClientConfig = tlsConfig
	clientConfig.HttpClient.Transport = transport
}

// Returns true if any of the following conditions are true:
//   * CA cert is configured
//   * CA path is configured
//   * configured to skip certificate verification
//   * TLS server name is configured
//
func (c *TOTPConfig) shouldSetTLSParameters() bool {
	return c.CACert != "" || c.CAPath != "" || c.TLSServerName != "" || c.TLSSkipVerify
}

// NewClient returns a new client for the configuration. This client will be used by the
// vault-totp-helper to communicate with Vault server and verify the OTP entered by user.
// If the configuration supplies Vault SSL certificates, then the client will
// have TLS configured in its transport.
func (c *TOTPConfig) NewClient() (*api.Client, error) {
	// Creating a default client configuration for communicating with vault server.
	clientConfig := api.DefaultConfig()

	// Pointing the client to the actual address of vault server.
	clientConfig.Address = c.VaultAddr

	// Check if certificates are provided via config file.
	if c.shouldSetTLSParameters() {
		rootConfig := &rootcerts.Config{
			CAFile: c.CACert,
			CAPath: c.CAPath,
		}
		certPool, err := rootcerts.LoadCACerts(rootConfig)
		if err != nil {
			return nil, err
		}
		// Enable TLS on the HTTP client information
		c.SetTLSParameters(clientConfig, certPool)
	}

	// Creating the client object for the given configuration
	client, err := api.NewClient(clientConfig)
	if err != nil {
		return nil, err
	}

	// Configure namespace
	if c.Namespace != "" {
		client.SetNamespace(c.Namespace)
	}

	return client, nil
}

// LoadTOTPConfig loads totp-helper's configuration from the file and populates the corresponding
// in-memory structure.
//
// Vault address is a required parameter.
// Mount point defaults to "totp".
func LoadTOTPConfig(path string) (*TOTPConfig, error) {
	contents, err := ioutil.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, multierror.Prefix(err, "totp_helper:")
	}
	return ParseTOTPConfig(string(contents))
}

func countTrue(bools ...bool) int {
	c := 0
	for _, v := range bools {
		if v {
			c += 1
		}
	}
	return c
}

// ParseTOTPConfig parses the given contents as a string for the TOTP
// configuration.
func ParseTOTPConfig(contents string) (*TOTPConfig, error) {
	root, err := hcl.Parse(string(contents))
	if err != nil {
		return nil, errwrap.Wrapf("error parsing config: {{err}}", err)
	}

	list, ok := root.Node.(*ast.ObjectList)
	if !ok {
		return nil, fmt.Errorf("error parsing config: file doesn't contain a root object")
	}

	valid := []string{
		"vault_addr",
		"totp_mount_point",
		"namespace",
		"ca_cert",
		"ca_path",
		"tls_skip_verify",
		"tls_server_name",
		"token_file",
		"role_id",
		"secret_id",
		"secret_file",
		"secret_env",
	}
	if err := hclutil.CheckHCLKeys(list, valid); err != nil {
		return nil, multierror.Prefix(err, "totp_helper:")
	}

	var c TOTPConfig
	c.TOTPMountPoint = TOTPDefaultMountPoint
	if err := hcl.DecodeObject(&c, list); err != nil {
		return nil, multierror.Prefix(err, "totp_helper:")
	}

	if c.VaultAddr == "" {
		return nil, fmt.Errorf(`missing config "vault_addr"`)
	}
	if countTrue(c.TokenFile != "", c.RoleID != "") > 1 {
		return nil, fmt.Errorf(`only one of "token_file" or "role_id" may be provided`)
	}
	numSecret := countTrue(c.SecretID != "", c.SecretFile != "", c.SecretEnv != "")
	if (c.RoleID == "" && numSecret > 0) || (c.RoleID != "" && numSecret != 1) {
		return nil, fmt.Errorf(`"role_id" must be accompanied by exactly one of "secret_id", "secret_file", "secret_env"`)
	}
	return &c, nil
}

func TOTPLogin(ctx context.Context, c *api.Client, config *TOTPConfig) error {
	if config.TokenFile != "" {
		token, err := ioutil.ReadFile(config.TokenFile)
		if err != nil {
			return err
		}
		c.SetToken(string(token))
		return nil
	}
	if config.RoleID != "" {
		cred := &approle.SecretID{
			FromString: config.SecretID,
			FromFile:   config.SecretFile,
			FromEnv:    config.SecretEnv,
		}
		appRoleAuth, err := approle.NewAppRoleAuth(config.RoleID, cred)
		if err != nil {
			return err
		}
		authInfo, err := c.Auth().Login(ctx, appRoleAuth)
		if err != nil {
			return err
		}
		if authInfo == nil {
			return fmt.Errorf("no auth info was returned")
		}
		return nil
	}
	if os.Getenv("VAULT_TOKEN") != "" {
		// This is picked up automatically
		return nil
	}
	return fmt.Errorf("No Vault authentication credentials set")
}

// Verify the TOTP response string provided by the user against the Vault server.
func TOTPVerify(c *api.Client, mountpoint, username, otp string) error {
	data := map[string]interface{}{
		"code": otp,
	}
	verifyPath := fmt.Sprintf("%s/code/%s", mountpoint, username)
	secret, err := c.Logical().Write(verifyPath, data)
	if err != nil {
		return err
	}

	var verifyResp TOTPVerifyResponse
	err = mapstructure.Decode(secret.Data, &verifyResp)
	if err != nil {
		return err
	}
	if verifyResp.Valid != true {
		return fmt.Errorf("Response is invalid")
	}
	return nil
}
