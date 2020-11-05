package main

import (
	"crypto/x509"
	"flag"
	"fmt"

	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/venafi/tpp"
)

func run() error {
	tppUrl := flag.String("tpp-url", "https://tpp.example.com", "The URL of the TPP server")
	tppZone := flag.String("tpp-zone", `Examples\Zone1\Policy1`, "The relative path to a TPP policy")
	tppUser := flag.String("tpp-user", "tpp-user", "The TPP user name")
	tppPassword := flag.String("tpp-password", "PASSWORD", "The TPP user password")
	limit := flag.Int("limit", 1, "The number of certificates to delete")
	flag.Parse()
	var emptyTrustCertPool *x509.CertPool

	c, err := tpp.NewConnector(
		*tppUrl,
		*tppZone,
		false,
		emptyTrustCertPool,
	)
	if err != nil {
		return fmt.Errorf("error creating TPP client: %v", err)
	}
	if err := c.Authenticate(&endpoint.Authentication{
		User:     *tppUser,
		Password: *tppPassword,
	}); err != nil {
		return fmt.Errorf("error authenticating: %v", err)
	}
	if err := c.DeleteCertificates(endpoint.Filter{
		Limit: limit,
	}); err != nil {
		return err
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		panic(err)
	}
}
