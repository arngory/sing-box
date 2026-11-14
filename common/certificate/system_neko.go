package certificate

import "crypto/x509"

// SystemCertificates are the platform's trusted roots where the core reads them itself: on Android all of
// AndroidCAStore, the roots its user installed among them and those they turned off left out; nil elsewhere, and
// where the platform gave none.
//
// neko: the app gives them to naive's Chromium as a file when its setting is the system's store (Chromium on Android
// takes roots besides Chrome's list only from SSL_CERT_FILE).
func SystemCertificates() []*x509.Certificate {
	return systemCertificates()
}
