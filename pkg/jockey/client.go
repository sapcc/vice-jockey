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

const SYMANTEC_INTERMEDIATE = `
-----BEGIN CERTIFICATE-----
MIIFODCCBCCgAwIBAgIQUT+5dDhwtzRAQY0wkwaZ/zANBgkqhkiG9w0BAQsFADCB
yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL
ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp
U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW
ZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0
aG9yaXR5IC0gRzUwHhcNMTMxMDMxMDAwMDAwWhcNMjMxMDMwMjM1OTU5WjB+MQsw
CQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNV
BAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxLzAtBgNVBAMTJlN5bWFudGVjIENs
YXNzIDMgU2VjdXJlIFNlcnZlciBDQSAtIEc0MIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAstgFyhx0LbUXVjnFSlIJluhL2AzxaJ+aQihiw6UwU35VEYJb
A3oNL+F5BMm0lncZgQGUWfm893qZJ4Itt4PdWid/sgN6nFMl6UgfRk/InSn4vnlW
9vf92Tpo2otLgjNBEsPIPMzWlnqEIRoiBAMnF4scaGGTDw5RgDMdtLXO637QYqzu
s3sBdO9pNevK1T2p7peYyo2qRA4lmUoVlqTObQJUHypqJuIGOmNIrLRM0XWTUP8T
L9ba4cYY9Z/JJV3zADreJk20KQnNDz0jbxZKgRb78oMQw7jW2FUyPfG9D72MUpVK
Fpd6UiFjdS8W+cRmvvW1Cdj/JwDNRHxvSz+w9wIDAQABo4IBYzCCAV8wEgYDVR0T
AQH/BAgwBgEB/wIBADAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vczEuc3ltY2Iu
Y29tL3BjYTMtZzUuY3JsMA4GA1UdDwEB/wQEAwIBBjAvBggrBgEFBQcBAQQjMCEw
HwYIKwYBBQUHMAGGE2h0dHA6Ly9zMi5zeW1jYi5jb20wawYDVR0gBGQwYjBgBgpg
hkgBhvhFAQc2MFIwJgYIKwYBBQUHAgEWGmh0dHA6Ly93d3cuc3ltYXV0aC5jb20v
Y3BzMCgGCCsGAQUFBwICMBwaGmh0dHA6Ly93d3cuc3ltYXV0aC5jb20vcnBhMCkG
A1UdEQQiMCCkHjAcMRowGAYDVQQDExFTeW1hbnRlY1BLSS0xLTUzNDAdBgNVHQ4E
FgQUX2DPYZBV34RDFIpgKrL1evRDGO8wHwYDVR0jBBgwFoAUf9Nlp8Ld7LvwMAnz
Qzn6Aq8zMTMwDQYJKoZIhvcNAQELBQADggEBAF6UVkndji1l9cE2UbYD49qecxny
H1mrWH5sJgUs+oHXXCMXIiw3k/eG7IXmsKP9H+IyqEVv4dn7ua/ScKAyQmW/hP4W
Ko8/xabWo5N9Q+l0IZE1KPRj6S7t9/Vcf0uatSDpCr3gRRAMFJSaXaXjS5HoJJtG
QGX0InLNmfiIEfXzf+YzguaoxX7+0AjiJVgIcWjmzaLmFN5OUiQt/eV5E1PnXi8t
TRttQBVSK/eHiXgSgW7ZTaoteNTCLD0IX4eRnh8OsN4wUmSGiaqdZpwOdgyA8nTY
Kvi4Os7X1g8RvmurFPW9QaAiY4nxug9vKWNmLT+sjHLF+8fk1A/yO0+MKcc=
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

		err = appendIntermediateCert(basename, SYMANTEC_INTERMEDIATE)

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
		}

		glog.Infof("Picked up certificate for %v", cr.CommonName)
		err = deleteTID(basename)
		if err != nil {
			glog.Errorf("Couldn't delete tid: %v", err)
		}

		err = appendIntermediateCert(basename, SYMANTEC_INTERMEDIATE)

		if err != nil {
			glog.Errorf("Couldn't append intermediate: %v", err)
		}
	}

	return nil
}

func Renew(configFile string) error {
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

		glog.V(5).Infof("Certificate %v is valid until %v", cr.CommonName, cert.NotAfter)

		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM([]byte(SYMANTEC_INTERMEDIATE))

		opts := x509.VerifyOptions{
			CurrentTime:   time.Now().AddDate(0, 1, 0),
			Intermediates: pool,
		}

		_, err = cert.Verify(opts)
		if err == nil {
			glog.V(3).Infof("Certificate is valid. %v: %v", cr.CommonName, err)
		} else {
			glog.Info("Certificate is expiring soon: %v: %v", cr.CommonName, err)
		}
	}

	return nil
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

func readKey(basename string) (key *rsa.PrivateKey, pem []byte, err error) {
	file := fmt.Sprintf("%s-key.pem", basename)

	if _, err = os.Stat(file); !os.IsNotExist(err) {
		pem, err = ioutil.ReadFile(file)
		if err == nil {
			key, err = x509.ParsePKCS1PrivateKey(pem)
		}
	} else {
		key, pem, err = newRSAKey()
		if err == nil {
			err = writeKey(basename, pem)
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
