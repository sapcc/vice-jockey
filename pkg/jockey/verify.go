package jockey

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"path/filepath"
	"time"

	"github.com/golang/glog"
)

func Validate(configFile string) error {
	config, err := loadConfig(configFile)
	if err != nil {
		return fmt.Errorf("Could read config-file: %v", err)
	}

	glog.Info("============================================================================")
	glog.Info("  Verifying Certificates")
	glog.Info("============================================================================")

	for _, cr := range config.Certificates {
		basename := filepath.Join(Workdir, cr.CommonName)

		certPEM, err := readCert(basename)
		if err != nil {
			glog.Infof("Couldn't read certificate for %v: %v. Skipping...", cr.CommonName, err)
			continue
		}

		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			glog.Infof("Failed to decode certificate for %v. Skipping...", cr.CommonName)
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			glog.Infof("Failed to parse certificate for %v. Skipping...", cr.CommonName)
			continue
		}

		dialer := &net.Dialer{Timeout: 2 * time.Second}
		options := &tls.Config{InsecureSkipVerify: true}
		conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%v:%v", cert.Subject.CommonName, 443), options)
		if err != nil {
			glog.Infof("Couldn't fetch remote certificate for %v: %v. Skipping...", cr.CommonName, err)
			continue
		}
		defer conn.Close()

		if conn.ConnectionState().PeerCertificates[0].Equal(cert) {
			glog.Infof("%v ok", cr.CommonName)
		} else {
			glog.Infof("%v missmatch", cr.CommonName)
			fmt.Println(cr.CommonName)
		}
	}

	return nil
}
