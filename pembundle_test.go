package cachedcert

import "testing"

func TestTLSCertFromCertAndKeyPEMBundle(t *testing.T) {
	bundle := testPEMBundle(t, "status.example.com")

	cert, err := tlsCertFromCertAndKeyPEMBundle(bundle)
	if err != nil {
		t.Fatalf("parsing bundle: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected at least one certificate in the chain")
	}
	if cert.PrivateKey == nil {
		t.Fatal("expected a private key")
	}
}

func TestTLSCertFromCertAndKeyPEMBundleRejectsKeyOnly(t *testing.T) {
	_, err := tlsCertFromCertAndKeyPEMBundle([]byte("not a pem block"))
	if err == nil {
		t.Fatal("expected an error for input with no PEM blocks")
	}
}
