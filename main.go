package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

// This binary will be run as a command with the goal of client authentication.
// This is not a PAM module per se, but binary fails if verification of OTP
// fails. The PAM configuration runs this binary as an external command via
// the pam_exec.so module as a 'requisite'. Essentially, if this binary fails,
// then the authentication fails.
func main() {
	err := Run(os.Args[1:])
	if err != nil {
		// All the errors are logged using this one statement. All the methods
		// simply return appropriate error message.
		log.Printf("[ERROR] %s", err)

		// Since this is not a PAM module, exiting with appropriate error
		// code does not make sense. Any non-zero exit value is considered
		// authentication failure.
		os.Exit(1)
	}
	os.Exit(0)
}

// Retrieves OTP from user and validates it with Vault server.
func Run(args []string) error {
	ctx := context.Background()

	for _, arg := range args {
		if arg == "version" || arg == "-v" || arg == "-version" || arg == "--version" {
			fmt.Println(formattedVersion())
			return nil
		}
	}

	var config string
	var dev bool
	flags := flag.NewFlagSet("totp-helper", flag.ContinueOnError)
	flags.StringVar(&config, "config", "", "")
	flags.BoolVar(&dev, "dev", false, "")

	flags.Usage = func() {
		fmt.Printf("%s\n", Help())
		os.Exit(1)
	}

	if err := flags.Parse(args); err != nil {
		return err
	}

	args = flags.Args()

	if len(config) == 0 {
		return fmt.Errorf("at least one config path must be specified with -config")
	}

	// Load the configuration for this helper
	clientConfig, err := LoadTOTPConfig(config)
	if err != nil {
		return err
	}

	if dev {
		log.Printf("==> WARNING: Dev mode is enabled!")
		if strings.HasPrefix(strings.ToLower(clientConfig.VaultAddr), "https://") {
			return fmt.Errorf("unsupported scheme in 'dev' mode")
		}
		clientConfig.CACert = ""
		clientConfig.CAPath = ""
	} else if strings.HasPrefix(strings.ToLower(clientConfig.VaultAddr), "http://") {
		return fmt.Errorf("unsupported scheme. use 'dev' mode")
	}

	// Get an http client to interact with Vault server based on the configuration
	client, err := clientConfig.NewClient()
	if err != nil {
		return err
	}

	// Logging namespace and TOTP mount point since TOTP backend mount point at Vault server
	// can vary and helper has no way of knowing these automatically. totp-helper reads
	// the namespace and mount point from the configuration file and uses the same to talk
	// to Vault. In case of errors, this can be used for debugging.
	//
	// If mount point is not mentioned in the config file, default mount point
	// of the TOTP backend will be used.
	log.Printf("[INFO] using TOTP mount point: %s", clientConfig.TOTPMountPoint)
	log.Printf("[INFO] using namespace: %s", clientConfig.Namespace)

	// PAM_USER represents the username for which authentication is being
	// requested.
	username := os.Getenv("PAM_USER")
	if username == "" {
		return fmt.Errorf("PAM_USER missing")
	}

	var otp string

	// Reading the one-time-password from the prompt. This is enabled
	// by supplying 'expose_authtok' option to pam module config.
	otpBytes, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return err
	}

	// Removing the terminator
	otp = strings.TrimSuffix(string(otpBytes), string('\x00'))
	if otp == "" {
		return fmt.Errorf("Empty OTP response")
	}

	// Login to Vault
	if err := AppRoleLogin(ctx, client, clientConfig.RoleID, clientConfig.SecretID); err != nil {
		return err
	}

	// Validate the response
	if err := TOTPVerify(client, clientConfig.TOTPMountPoint, username, otp); err != nil {
		return err
	}

	log.Printf("[INFO] Response is valid")
	return nil
}

func Help() string {
	helpText := `
Usage: vault-totp-helper [options]

  vault-totp-helper takes the One-Time-Password (OTP) from the client and
  validates it with Vault server. This binary should be used as an external
  command for authenticating clients during for keyboard-interactive auth
  of TOTP server.

Options:

  -config=<path>              The path on disk to a configuration file.
  -dev                        Run the helper in "dev" mode, (such as testing or http)
  -version                    Display version.
`
	return strings.TrimSpace(helpText)
}
