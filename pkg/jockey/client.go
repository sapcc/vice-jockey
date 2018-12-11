package jockey

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	yaml "gopkg.in/yaml.v2"

	"github.com/golang/glog"
	vice "github.com/sapcc/go-vice"
)

const DIGICERT_INTERMEDIATE = `
-----BEGIN CERTIFICATE-----
MIIElDCCA3ygAwIBAgIQAf2j627KdciIQ4tyS8+8kTANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0xMzAzMDgxMjAwMDBaFw0yMzAzMDgxMjAwMDBaME0xCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxJzAlBgNVBAMTHkRpZ2lDZXJ0IFNIQTIg
U2VjdXJlIFNlcnZlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ANyuWJBNwcQwFZA1W248ghX1LFy949v/cUP6ZCWA1O4Yok3wZtAKc24RmDYXZK83
nf36QYSvx6+M/hpzTc8zl5CilodTgyu5pnVILR1WN3vaMTIa16yrBvSqXUu3R0bd
KpPDkC55gIDvEwRqFDu1m5K+wgdlTvza/P96rtxcflUxDOg5B6TXvi/TC2rSsd9f
/ld0Uzs1gN2ujkSYs58O09rg1/RrKatEp0tYhG2SS4HD2nOLEpdIkARFdRrdNzGX
kujNVA075ME/OV4uuPNcfhCOhkEAjUVmR7ChZc6gqikJTvOX6+guqw9ypzAO+sf0
/RR3w6RbKFfCs/mC/bdFWJsCAwEAAaOCAVowggFWMBIGA1UdEwEB/wQIMAYBAf8C
AQAwDgYDVR0PAQH/BAQDAgGGMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYY
aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMHsGA1UdHwR0MHIwN6A1oDOGMWh0dHA6
Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RDQS5jcmwwN6A1
oDOGMWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RD
QS5jcmwwPQYDVR0gBDYwNDAyBgRVHSAAMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8v
d3d3LmRpZ2ljZXJ0LmNvbS9DUFMwHQYDVR0OBBYEFA+AYRyCMWHVLyjnjUY4tCzh
xtniMB8GA1UdIwQYMBaAFAPeUDVW0Uy7ZvCj4hsbw5eyPdFVMA0GCSqGSIb3DQEB
CwUAA4IBAQAjPt9L0jFCpbZ+QlwaRMxp0Wi0XUvgBCFsS+JtzLHgl4+mUwnNqipl
5TlPHoOlblyYoiQm5vuh7ZPHLgLGTUq/sELfeNqzqPlt/yGFUzZgTHbO7Djc1lGA
8MXW5dRNJ2Srm8c+cftIl7gzbckTB+6WohsYFfZcTEDts8Ls/3HB40f/1LkAtDdC
2iDJ6m6K7hQGrn2iWZiIqBtvLfTyyRRfJs8sjX7tN8Cp1Tm5gr8ZDOo0rwAhaPit
c+LJMto4JQtV05od8GiG7S5BNO98pVAdvzr508EIDObtHopYJeS4d60tbvVS3bR0
j6tJLp07kzQoH3jOlOrHvdPJbRzeXDLz
-----END CERTIFICATE-----`

func NewViceClient(certFile, keyFile string) (*vice.Client, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("Couldn't load authentication keypair: %v", err)
	}

	return vice.New(cert), nil
}

func Enroll(configFile string) error {
	viceClient, err := NewViceClient(CertFile, KeyFile)
	if err != nil {
		return fmt.Errorf("Could create vice-client: %v", err)
	}

	config, err := loadConfig(configFile)
	if err != nil {
		return fmt.Errorf("Could read config-file: %v", err)
	}

	glog.Info("============================================================================")
	glog.Info("  Requesting Certificates")
	glog.Info("============================================================================")

	for _, cr := range config.Certificates {
		basename := filepath.Join(Workdir, cr.CommonName)

		tid, err := readTID(basename)
		if tid != "" {
			glog.Infof("Pending certificate for %v. Skipping...", cr.CommonName)
			continue
		}

		_, err = readCert(basename)
		if err == nil {
			glog.Infof("Existing certificate for %v. Skipping...", cr.CommonName)
			continue
		}

		glog.Infof("Enrolling certificate for %v.", cr.CommonName)

		key, _, err := readKey(basename)
		if err != nil {
			glog.Fatalf("Key failed: %v", err)
		}

		csr, err := newRawCSR(cr.CommonName, config.Defaults.Email, cr.SANS, key)
		if err != nil {
			glog.Fatalf("Generating CSR failed: %v", err)
		}

		err = writeCSR(basename, csr)
		if err != nil {
			glog.Fatalf("Writing CSR failed: %v", err)
		}

		enrollRequest := &vice.EnrollRequest{
			Challenge:          config.Defaults.Challenge,
			CertProductType:    vice.CertProductType.Server,
			FirstName:          config.Defaults.FirstName,
			LastName:           config.Defaults.LastName,
			Email:              config.Defaults.Email,
			CSR:                string(csr),
			ServerType:         vice.ServerType.OpenSSL,
			EmployeeId:         config.Defaults.EmployeeId,
			SignatureAlgorithm: vice.SignatureAlgorithm.SHA256WithRSAEncryption,
			SubjectAltNames:    cr.SANS,
			ValidityPeriod:     vice.ValidityPeriod.OneYear,
		}

		ctx := context.TODO()
		enrollment, err := viceClient.Certificates.Enroll(ctx, enrollRequest)
		if err != nil {
			glog.Errorf("%s", err)
			continue
		} else {
			err = writeTID(basename, enrollment.TransactionID)
			if err != nil {
				glog.Fatalf("Writing TID failed: %v", err)
			}
		}
	}

	return nil
}

func Approve(configFile string) error {
	viceClient, err := NewViceClient(CertFile, KeyFile)
	if err != nil {
		return fmt.Errorf("Could create vice-client: %v", err)
	}

	config, err := loadConfig(configFile)
	if err != nil {
		return fmt.Errorf("Could read config-file: %v", err)
	}

	glog.Info("============================================================================")
	glog.Info("  Approving Certificates")
	glog.Info("============================================================================")

	for _, cr := range config.Certificates {
		basename := filepath.Join(Workdir, cr.CommonName)

		tid, err := readTID(basename)
		if err != nil {
			glog.V(5).Infof("Skipping approval of %v. No TID found", cr.CommonName)
			continue
		}

		glog.V(5).Infof("Approving %v in transaction %v", cr.CommonName, tid)
		approval, err := viceClient.Certificates.Approve(context.TODO(), &vice.ApprovalRequest{TransactionID: tid})

		if err != nil {
			glog.Errorf("Couldn't approve certificate for transaction %v: %v", tid, err)
			continue
		}

		err = writeCert(basename, approval.Certificate)
		if err != nil {
			glog.Errorf("Couldn't write cert: %v", err)
		}

		glog.Infof("Picked up certificate for %v", cr.CommonName)
		err = deleteTID(basename)
		if err != nil {
			glog.Errorf("Couldn't delete tid: %v", err)
		}

		err = appendIntermediateCert(basename, DIGICERT_INTERMEDIATE)

		if err != nil {
			glog.Errorf("Couldn't append intermediate: %v", err)
		}
	}

	return nil
}

func Pickup(configFile string) error {
	viceClient, err := NewViceClient(CertFile, KeyFile)
	if err != nil {
		return fmt.Errorf("Could create vice-client: %v", err)
	}

	config, err := loadConfig(configFile)
	if err != nil {
		return fmt.Errorf("Could read config-file: %v", err)
	}

	glog.Info("============================================================================")
	glog.Info("  Picking Up New Certificates")
	glog.Info("============================================================================")

	for _, cr := range config.Certificates {
		basename := filepath.Join(Workdir, cr.CommonName)

		tid, err := readTID(basename)
		if err != nil {
			glog.V(5).Infof("Skipping download of %v. No TID found", cr.CommonName)
			continue
		}

		glog.V(5).Infof("Fetching certificate %v in transaction %v", cr.CommonName, tid)
		pickup, err := viceClient.Certificates.Pickup(context.TODO(), &vice.PickupRequest{TransactionID: tid})

		if err != nil {
			glog.Errorf("Couldn't pickup certificate for transaction %v: %v", tid, err)
			continue
		}

		err = writeCert(basename, pickup.Certificate)
		if err != nil {
			glog.Errorf("Couldn't write cert: %v", err)
			continue
		}

		glog.Infof("Picked up certificate for %v", cr.CommonName)
		err = deleteTID(basename)
		if err != nil {
			glog.Errorf("Couldn't delete tid: %v", err)
		}

		err = appendIntermediateCert(basename, DIGICERT_INTERMEDIATE)

		if err != nil {
			glog.Errorf("Couldn't append intermediate: %v", err)
			continue
		}
	}

	return nil
}

func Renew(configFile string) error {
	viceClient, err := NewViceClient(CertFile, KeyFile)
	if err != nil {
		return fmt.Errorf("Could create vice-client: %v", err)
	}

	config, err := loadConfig(configFile)
	if err != nil {
		return fmt.Errorf("Could read config-file: %v", err)
	}

	glog.Info("============================================================================")
	glog.Info("  Renewing Expired Certificates")
	glog.Info("============================================================================")

	for _, cr := range config.Certificates {
		basename := filepath.Join(Workdir, cr.CommonName)

		raw, err := readCert(basename)
		if err != nil {
			glog.Errorf("Couldn't read certificate for %v: %v", cr.CommonName, err)
			continue
		}

		block, _ := pem.Decode([]byte(raw))
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			glog.Errorf("Couldn't parse certificate for %v: %v", cr.CommonName, err)
			continue
		}

		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM([]byte(DIGICERT_INTERMEDIATE))

		opts := x509.VerifyOptions{
			CurrentTime:   time.Now().AddDate(0, 3, 0),
			Intermediates: pool,
		}

		_, err = cert.Verify(opts)
		if err != nil {
			glog.Infof("%v is expiring soon: %v", cr.CommonName, cert.NotAfter)
			renew(viceClient, config, cr)
		} else {
			glog.V(5).Infof("%v is valid until: %v", cr.CommonName, cert.NotAfter)
		}
	}

	return nil
}

func renew(viceClient *vice.Client, config *Config, cr Certificate) {
	glog.Infof("Renewing certificate for %v.", cr.CommonName)

	basename := filepath.Join(Workdir, cr.CommonName)

	key, _, err := readKey(basename)
	if err != nil {
		glog.Fatalf("Key failed: %v", err)
	}

	csr, err := newRawCSR(cr.CommonName, config.Defaults.Email, cr.SANS, key)
	if err != nil {
		glog.Fatalf("Generating CSR failed: %v", err)
	}

	err = writeCSR(basename, csr)
	if err != nil {
		glog.Fatalf("Writing CSR failed: %v", err)
	}

	renewRequest := &vice.RenewRequest{
		FirstName:          config.Defaults.FirstName,
		LastName:           config.Defaults.LastName,
		Email:              config.Defaults.Email,
		CSR:                string(csr),
		SubjectAltNames:    cr.SANS,
		OriginalChallenge:  config.Defaults.Challenge,
		Challenge:          config.Defaults.Challenge,
		CertProductType:    vice.CertProductType.Server,
		ServerType:         vice.ServerType.OpenSSL,
		ValidityPeriod:     vice.ValidityPeriod.OneYear,
		SignatureAlgorithm: vice.SignatureAlgorithm.SHA256WithRSAEncryption,
	}

	tid, err := readTID(basename)
	if tid != "" {
		renewRequest.OriginalTransactionID = tid
	} else {
		original, err := readCert(basename)
		if err != nil {
			glog.Errorf("Couldn't read TID or original certificate for %v. Skipping...", cr.CommonName)
			return
		} else {
			renewRequest.OriginalCertificate = original
		}
	}

	ctx := context.TODO()
	renewal, err := viceClient.Certificates.Renew(ctx, renewRequest)

	if err != nil {
		glog.Errorf("Couldn't renew certificate for transaction %v: %v", tid, err)
		return
	}

	err = writeCert(basename, renewal.Certificate)
	if err != nil {
		glog.Errorf("Couldn't write cert: %v", err)
		return
	}

	err = appendIntermediateCert(basename, DIGICERT_INTERMEDIATE)

	if err != nil {
		glog.Errorf("Couldn't append intermediate: %v", err)
	}
}

func loadConfig(configFile string) (*Config, error) {
	yamlFile, err := ioutil.ReadFile(configFile)

	if err != nil {
		return nil, err
	}

	var config Config

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func readTID(basename string) (string, error) {
	file := fmt.Sprintf("%s.tid", basename)

	if _, err := os.Stat(file); os.IsNotExist(err) {
		return "", fmt.Errorf("No TID found")
	}

	tid, err := ioutil.ReadFile(file)
	if err != nil {
		return "", err
	}

	return string(tid), nil
}

func readCert(basename string) (string, error) {
	file := fmt.Sprintf("%s.pem", basename)

	if _, err := os.Stat(file); os.IsNotExist(err) {
		return "", fmt.Errorf("No PEM found")
	}

	pem, err := ioutil.ReadFile(file)
	if err != nil {
		return "", err
	}

	return string(pem), nil
}

func readKey(basename string) (key *rsa.PrivateKey, raw []byte, err error) {
	file := fmt.Sprintf("%s-key.pem", basename)

	if _, err = os.Stat(file); !os.IsNotExist(err) {
		io, err := ioutil.ReadFile(file)
		if err != nil {
			return nil, nil, err
		}

		block, _ := pem.Decode(io)
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else {
		key, raw, err = newRSAKey()
		if err == nil {
			err = writeKey(basename, raw)
		}
	}

	return
}

func newRawCSR(commonName string, email string, sans []string, key *rsa.PrivateKey) ([]byte, error) {
	name := pkix.Name{
		CommonName:         commonName,
		Country:            []string{"DE"},
		Province:           []string{"BERLIN"},
		Locality:           []string{"BERLIN"},
		Organization:       []string{"SAP SE"},
		OrganizationalUnit: []string{"Infrastructure Automization"},
	}

	return vice.CreateCSR(name, email, sans, key)
}

func writeCSR(basename string, pem []byte) error {
	return ioutil.WriteFile(fmt.Sprintf("%s.csr", basename), pem, 0644)
}

func writeTID(basename, tid string) error {
	return ioutil.WriteFile(fmt.Sprintf("%s.tid", basename), []byte(tid), 0644)
}

func newRSAKey() (*rsa.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	block := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(key),
	}

	return key, pem.EncodeToMemory(&block), nil
}

func writeKey(basename string, pem []byte) error {
	return ioutil.WriteFile(fmt.Sprintf("%s-key.pem", basename), pem, 0644)
}

func writeCert(basename, pem string) error {
	return ioutil.WriteFile(fmt.Sprintf("%s.pem", basename), []byte(pem), 0644)
}

func deleteTID(basename string) error {
	return os.Remove(fmt.Sprintf("%s.tid", basename))
}

func appendIntermediateCert(basename, pem string) error {
	f, err := os.OpenFile(fmt.Sprintf("%s.pem", basename), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	defer f.Close()

	if _, err = f.WriteString(pem); err != nil {
		return err
	}

	return nil
}
