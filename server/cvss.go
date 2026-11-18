package server

import "strings"

// CVSS mapping is deterministic: one vector per vulnerability class, chosen from
// the class alone. The score is computed from the vector, so two runs of the same
// finding always get the same number and a reviewer can audit the vector to
// disagree with it. A finding whose class has no mapping falls back to a vector
// chosen from its severity band, which is the honest thing to do — the alternative
// is a blank field the reader has to guess about.

type cvssMap struct {
	vector string
	// scoreOverride is nil for a genuine v3.1 vector (computed from it). A
	// non-nil value means "no defensible vector, but the severity band implies
	// this base score" and the field is rendered with that caveat.
	scoreOverride *float64
}

func cvssPtr(v float64) *float64 { return &v }

// cvssForClass returns (score string, vector string). Both are empty when there
// is no mapping at all, which the template renders as "not scored".
func cvssForClass(class, severity string) (string, string) {
	c := strings.ToLower(class)
	var m cvssMap
	var ok bool
	m, ok = cvssClassMap[c]
	if !ok {
		// substring guards: class strings vary between agents
		for key, mm := range cvssClassMap {
			if strings.Contains(c, key) {
				m = mm
				ok = true
				break
			}
		}
	}
	if !ok {
		m, ok = cvssSevFallback[strings.ToLower(strings.TrimSpace(severity))]
	}
	if !ok {
		return "", ""
	}
	if m.scoreOverride != nil {
		return cvssFmt(*m.scoreOverride), m.vector
	}
	s := cvssScore(m.vector)
	if s < 0 {
		return "", m.vector
	}
	return cvssFmt(s), m.vector
}

var cvssClassMap = map[string]cvssMap{
	// XSS (reflected & stored): user interaction required, changed scope, low
	// privileges needed for stored. Network, no integrity on host, high impact on
	// victim's browser.
	"cross-site scripting (reflected)": {vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
	"cross-site scripting (stored)":    {vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N"},
	"cross-site scripting (dom)":       {vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},

	// CSRF: needs a victim session and a click, no confidentiality impact on the
	// attacker, integrity impact on the victim.
	"cross-site request forgery (csrf)": {vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"},

	// Insecure cookie flags: the finding is exposure of the session to a network
	// attacker who can already see traffic or run script. Adjacent network, no
	// integrity, the score reflects "enables other attacks" rather than a direct
	// compromise.
	"insecure cookie flags": {vector: "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"},

	// Missing security headers: lowest of the set. No direct compromise, it
	// removes a layer of defence against other attacks.
	"missing security headers": {vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"},

	// A few classes seen across T1P engagements so the map covers more than
	// this one report.
	"sql injection":                      {vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	"command injection":                  {vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	"authentication bypass":              {vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"},
	"idor":                               {vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
	"open redirect":                      {vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"},
	"server-side request forgery (ssrf)": {vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"},
	"local file inclusion":               {vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
	"path traversal":                     {vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
	"remote code execution":              {vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	"deserialization":                    {vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	"information disclosure":             {vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
}

var cvssSevFallback = map[string]cvssMap{
	"critical": {vector: "(severity band: critical)", scoreOverride: cvssPtr(9.0)},
	"high":     {vector: "(severity band: high)", scoreOverride: cvssPtr(7.5)},
	"medium":   {vector: "(severity band: medium)", scoreOverride: cvssPtr(5.0)},
	"low":      {vector: "(severity band: low)", scoreOverride: cvssPtr(3.0)},
	"info":     {vector: "(severity band: info)", scoreOverride: cvssPtr(0.0)},
}

// CVSSMetric is one editable v3.1 metric as the operator set it for a target.
type CVSSMetric struct {
	Value  string `json:"value"`
	Req    string `json:"req,omitempty"` // CR/IR/AR tier: L|M|H
	Reason string `json:"reason,omitempty"`
}

// CVSSProfile is the target's environmental context: the operator's stated answer
// to "what does this deployment actually look like", captured once and applied to
// every finding's vector. Every adjustment carries a reason so a reviewer can
// audit it instead of trusting a number.
type CVSSProfile struct {
	BusinessContext string `json:"business_context,omitempty"`
	Scope           string `json:"scope,omitempty"`

	ModifiedAV *CVSSMetric `json:"modified_av,omitempty"`
	ModifiedAC *CVSSMetric `json:"modified_ac,omitempty"`
	ModifiedPR *CVSSMetric `json:"modified_pr,omitempty"`
	ModifiedUI *CVSSMetric `json:"modified_ui,omitempty"`
	ModifiedS  *CVSSMetric `json:"modified_s,omitempty"`
	ModifiedC  *CVSSMetric `json:"modified_c,omitempty"`
	ModifiedI  *CVSSMetric `json:"modified_i,omitempty"`
	ModifiedA  *CVSSMetric `json:"modified_a,omitempty"`

	CR *CVSSMetric `json:"cr,omitempty"`
	IR *CVSSMetric `json:"ir,omitempty"`
	AR *CVSSMetric `json:"ar,omitempty"`

	CompensatingControls string `json:"compensating_controls,omitempty"`
}

// isEmpty reports whether a profile adjusts anything. An empty profile means the
// environmental score equals the base score, which is legitimate but must be
// stated, not silently applied.
func (p *CVSSProfile) isEmpty() bool {
	if p == nil {
		return true
	}
	return p.ModifiedAV == nil && p.ModifiedAC == nil && p.ModifiedPR == nil &&
		p.ModifiedUI == nil && p.ModifiedS == nil && p.ModifiedC == nil &&
		p.ModifiedI == nil && p.ModifiedA == nil &&
		p.CR == nil && p.IR == nil && p.AR == nil
}

// hasAnyReason reports whether the operator justified anything. A profile that
// changes a metric without a reason is exactly the invented number the gate
// exists to prevent.
func (p *CVSSProfile) hasAnyReason() bool {
	if p == nil {
		return false
	}
	for _, m := range []*CVSSMetric{p.ModifiedAV, p.ModifiedAC, p.ModifiedPR, p.ModifiedUI,
		p.ModifiedS, p.ModifiedC, p.ModifiedI, p.ModifiedA, p.CR, p.IR, p.AR} {
		if m != nil && strings.TrimSpace(m.Reason) != "" {
			return true
		}
	}
	return strings.TrimSpace(p.BusinessContext) != "" || strings.TrimSpace(p.CompensatingControls) != ""
}

// applyEnvironmental rescores a base vector against the operator's profile and
// returns (score, adjustedVector, applied). applied=false means the profile did
// not adjust this vector, so the caller keeps the base score and says so.
//
// The environmental score is computed FROM the metrics, exactly as cvssScore does
// for the base — never a class/severity modifier bolted on. A modified metric
// replaces its Base counterpart; a requirement (CR/IR/AR) rescales its CIA term.
func applyEnvironmental(baseVector string, p *CVSSProfile) (float64, string, bool) {
	if p == nil || p.isEmpty() {
		return -1, "", false
	}
	m := map[string]string{}
	for _, part := range strings.Split(baseVector, "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	if baseVector == "" || m["AV"] == "" {
		return -1, "", false
	}
	over := func(cur string, mm *CVSSMetric) string {
		if mm != nil && mm.Value != "" {
			return strings.ToUpper(strings.TrimSpace(mm.Value))
		}
		return cur
	}
	m["AV"] = over(m["AV"], p.ModifiedAV)
	m["AC"] = over(m["AC"], p.ModifiedAC)
	m["PR"] = over(m["PR"], p.ModifiedPR)
	m["UI"] = over(m["UI"], p.ModifiedUI)
	m["S"] = over(m["S"], p.ModifiedS)
	m["C"] = over(m["C"], p.ModifiedC)
	m["I"] = over(m["I"], p.ModifiedI)
	m["A"] = over(m["A"], p.ModifiedA)

	// Requirement tiers rescale the CIA impact weights: H=1.0 (no change),
	// M=0.75, L=0.5. A low confidentiality requirement means losing C matters
	// less to this deployment.
	reqMul := func(r *CVSSMetric) float64 {
		if r == nil || r.Req == "" {
			return 1.0
		}
		switch strings.ToUpper(strings.TrimSpace(r.Req)) {
		case "H":
			return 1.0
		case "M":
			return 0.75
		case "L":
			return 0.5
		}
		return 1.0
	}

	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	var pr float64
	if m["S"] == "C" {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}[m["PR"]]
	} else {
		pr = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[m["PR"]]
	}
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}[m["C"]] * reqMul(p.CR)
	iia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}[m["I"]] * reqMul(p.IR)
	aia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}[m["A"]] * reqMul(p.AR)

	iss := 1 - (1-cia)*(1-iia)*(1-aia)
	var impact float64
	if m["S"] == "U" {
		impact = 6.42 * iss
	} else {
		d := iss - 0.02
		if d < 0 {
			d = 0
		}
		impact = 7.52*(iss-0.029) - 3.25*pow15(d)
	}
	exploit := 8.22 * av * ac * pr * ui
	if impact <= 0 {
		return 0, renderAdjustedVector(m), true
	}
	var raw float64
	if m["S"] == "U" {
		raw = min3(impact+exploit, 10)
	} else {
		raw = min3(1.08*(impact+exploit), 10)
	}
	return roundup1(raw), renderAdjustedVector(m), true
}

// renderAdjustedVector rebuilds the vector string the environmental score came
// from, so the report shows the exact metrics rather than an unexplained number.
func renderAdjustedVector(m map[string]string) string {
	order := []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
	out := "CVSS:3.1"
	for _, k := range order {
		if v, ok := m[k]; ok && v != "" {
			out += "/" + k + ":" + v
		}
	}
	return out
}

// cvssScore computes a v3.1 base score from a vector string. Returns -1 on a
// vector it cannot parse rather than a plausible-looking number.
func cvssScore(v string) float64 {
	m := map[string]string{}
	for _, part := range strings.Split(v, "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		m[kv[0]] = kv[1]
	}
	if m["AV"] == "" || m["AC"] == "" || m["PR"] == "" || m["UI"] == "" ||
		m["S"] == "" || m["C"] == "" || m["I"] == "" || m["A"] == "" {
		return -1
	}
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	prUnchanged := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[m["PR"]]
	prChanged := map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}[m["PR"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}[m["C"]]
	iia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}[m["I"]]
	aia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}[m["A"]]
	var iss, impact float64
	if m["S"] == "U" {
		iss = 1 - (1-cia)*(1-iia)*(1-aia)
		impact = 6.42 * iss
	} else {
		// v3.1 changed-scope impact: 7.52*(ISS-0.029) - 3.25*(ISS-0.02)^15.
		// The exponent is 15, not 3 — using 3 under-scores every scope-changing
		// finding (a reflected XSS scored 5.8 instead of 6.1).
		iss = 1 - (1-cia)*(1-iia)*(1-aia)
		d := iss - 0.02
		if d < 0 {
			d = 0
		}
		impact = 7.52*(iss-0.029) - 3.25*pow15(d)
	}
	exploit := 8.22 * av * ac * prUnchanged * ui
	if m["S"] == "C" {
		exploit = 8.22 * av * ac * prChanged * ui
	}
	if impact <= 0 {
		return 0
	}
	if m["S"] == "U" {
		return roundup1(min3(impact+exploit, 10))
	}
	return roundup1(min3(1.08*(impact+exploit), 10))
}

// pow15 is x^15 by squaring, avoiding a float-pow dependency for one exponent.
func pow15(x float64) float64 {
	x2 := x * x
	x4 := x2 * x2
	x8 := x4 * x4
	return x8 * x4 * x2 * x // 8+4+2+1
}

// roundup1 is the CVSS-mandated roundup: the smallest number with one decimal
// that is >= v. The calculator rounds to nearest, which reads one notch low on
// some vectors and breaks comparability with nvd/cvss-calculator.
func roundup1(v float64) float64 {
	// guard against float representation (6.007 landing as 6.0069999)
	const eps = 1e-9
	scaled := v * 10
	floored := float64(int(scaled))
	if scaled-floored > eps {
		floored++
	}
	return floored / 10
}

func round1(v float64) float64 { return float64(int(v*10+0.5)) / 10 }

func min3(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func cvssFmt(v float64) string {
	// one decimal, matching the CVSS calculator's presentation
	s := round1(v)
	return trimZero(s)
}

func trimZero(v float64) string {
	// format without pulling in strconv for a trailing ".0"
	if v == float64(int(v)) {
		return itoa(int(v)) + ".0"
	}
	// one decimal place is guaranteed by round1
	return itoa(int(v*10)/10) + "." + itoa(int(v*10)%10)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}
