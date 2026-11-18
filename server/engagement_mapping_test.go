package server

import "testing"

// The attack-pattern classifier must not dump every misconfiguration/DNS/TLS/
// header finding into the generic T1190 "Exploit Public-Facing Application"
// bucket. A report that maps a missing DMARC record to an exploitation technique
// is technically populated but analytically wrong — the reader sees a MITRE id
// that misrepresents what the finding actually is. These cases pin the specific
// mappings for the config/DNS/TLS/header classes seen in real engagements
// (gurufintek run 91 dumped all four into T1190 / WSTG-INFO-01).
func TestAttackMappingConfigDNSTLSHeader(t *testing.T) {
	cases := []struct {
		class     string
		wantMitre string
		wantWstg  string
	}{
		// DNS / email authentication
		{"email_spoofing_dmarc_missing", "T1566", "WSTG-CONF-13"},
		{"missing DMARC and CAA records", "T1566", "WSTG-CONF-13"},
		{"spf_record_absent", "T1566", "WSTG-CONF-13"},
		{"caa_record_missing", "T1583.001", "WSTG-CONF-09"},
		{"dnssec_not_enabled", "T1583.001", "WSTG-CONF-09"},
		// Transport security
		{"tls_deprecated_protocol_and_weak_cipher", "T1600.001", "WSTG-CRYP-01"},
		{"weak ssl configuration", "T1600.001", "WSTG-CRYP-01"},
		// Web hardening headers
		{"weak_content_security_policy", "T1189", "WSTG-CONF-14"},
		{"missing_security_headers", "T1189", "WSTG-CONF-07"},
		{"missing COEP/CORP cross-origin isolation", "T1189", "WSTG-CONF-07"},
		{"insecure cookie flags httponly samesite", "T1185", "WSTG-SESS-02"},
	}
	for _, c := range cases {
		mid, _ := mitreFor(c.class)
		wid, _ := wstgFor(c.class)
		if mid != c.wantMitre {
			t.Errorf("mitreFor(%q) = %s, want %s", c.class, mid, c.wantMitre)
		}
		if wid != c.wantWstg {
			t.Errorf("wstgFor(%q) = %s, want %s", c.class, wid, c.wantWstg)
		}
	}
}

// Injection / access-control classes must keep their existing precise mappings —
// adding the config/DNS/header cases above must not change them.
func TestAttackMappingInjectionUnchanged(t *testing.T) {
	cases := []struct {
		class     string
		wantMitre string
		wantWstg  string
	}{
		{"reflected xss", "T1059.007", "WSTG-INPV-01"},
		{"stored xss", "T1059.007", "WSTG-INPV-02"},
		{"csrf on deletesnippet", "T1185", "WSTG-SESS-05"},
		{"sql injection in q", "T1190", "WSTG-INPV-05"},
		{"idor on user object", "T1190", "WSTG-ATHZ-04"},
	}
	for _, c := range cases {
		mid, _ := mitreFor(c.class)
		wid, _ := wstgFor(c.class)
		if mid != c.wantMitre {
			t.Errorf("mitreFor(%q) = %s, want %s", c.class, mid, c.wantMitre)
		}
		if wid != c.wantWstg {
			t.Errorf("wstgFor(%q) = %s, want %s", c.class, wid, c.wantWstg)
		}
	}
}
