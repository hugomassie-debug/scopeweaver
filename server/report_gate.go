package server

// The report gate enforces one rule: a finished engagement report is a claim of
// completeness, so it is not rendered until the underlying analysis is complete.
// An incomplete run still writes its five raw logs (those are data, and data is
// never withheld), but it refuses to emit the polished HTML/PDF/DOCX/PPTX that a
// client would read as "this is the whole picture".
//
// This exists because a report that looks finished but silently drops vectors is
// worse than no report: the reader cannot see the gap. Refusing to render is the
// honest signal.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// GateVerdict is the outcome of assessing one run against the completeness bar.
type GateVerdict struct {
	// Complete is true only when every blocking requirement is met. When false,
	// the report formats are withheld and Missing names each unmet requirement.
	Complete bool
	// Missing lists each requirement that is not satisfied, in plain language a
	// reader can act on.
	Missing []string
	// Warnings lists conditions that do not block rendering but should be stated
	// in the report itself (a failed or blocked run, non-browser vectors without
	// screenshot evidence).
	Warnings []string
	// Reason is the one-line explanation returned to a caller that asked for a
	// report and was refused.
	Reason string
}

// assessReportGate decides whether a run has earned a report. The bar:
//
//   - the operator set an environmental CVSS profile with a rationale (a report
//     without target context is base scores pretending to be prioritised — the
//     same finding on an internet-facing box and on an isolated lab box are not
//     the same risk)
//   - every finding carries a CVSS base score (a finding without a score is an
//     un-prioritised finding, and a client cannot act on priority ordering that
//     skips one)
//   - every finding carries remediation (a finding without a fix is a finding
//     half-delivered)
//   - every browser-demonstrable finding carries screenshot evidence
//     (confirmed ≠ proven — a response code is not a PoC-of-impact)
//
// A run with zero findings passes trivially: there is nothing to under-deliver on,
// and "no findings" is a legitimate result.
func (c *EngagementCollector) assessReportGate(ctx context.Context, runID int64) (GateVerdict, error) {
	v := GateVerdict{Complete: true}

	// Count the reportable findings first so the environmental-profile requirement
	// only bites when there is something to score. A run with zero findings has
	// nothing to contextualise.
	var total int
	_ = c.DB.QueryRowContext(ctx, `
		SELECT count(*) FROM eng_attack_mapping m
		  JOIN findings f ON f.id=m.finding_id
		 WHERE m.run_id=$1
		   AND COALESCE(f.status,'') NOT IN ('duplicate','false_positive')`, runID).Scan(&total)

	// 1. Environmental profile — blocking.
	profile, err := c.loadCVSSProfile(ctx, runID)
	if err != nil {
		return v, fmt.Errorf("load cvss profile: %w", err)
	}
	if total > 0 && (profile == nil || profile.isEmpty()) {
		v.Complete = false
		v.Missing = append(v.Missing, fmt.Sprintf(
			"no environmental CVSS profile set for this target: POST /api/engagement/cvss-profile "+
				"with the target's context (scope, criticality, compensating controls) so every finding "+
				"can be scored against how this deployment actually looks, not just its base vector"))
	} else if total > 0 && !profile.hasAnyReason() {
		v.Complete = false
		v.Missing = append(v.Missing,
			"environmental CVSS profile adjusts metrics without a rationale: every adjustment must carry a reason")
	}

	// Findings that reach the report = de-duplicated, not duplicate/false_positive.
	rows, err := c.DB.QueryContext(ctx, `
		SELECT m.finding_id, f.vulnclass, f.severity, f.name,
		       COALESCE(m.status,''), COALESCE(m.evidence_shot,'')
		  FROM eng_attack_mapping m
		  JOIN findings f ON f.id=m.finding_id
		 WHERE m.run_id=$1
		   AND COALESCE(f.status,'') NOT IN ('duplicate','false_positive')`, runID)
	if err != nil {
		return v, err
	}
	defer rows.Close()

	var noCVSS, noRemed, noEvidence []string
	for rows.Next() {
		var id int64
		var class, sev, name, status, shot string
		if err := rows.Scan(&id, &class, &sev, &name, &status, &shot); err != nil {
			return v, err
		}
		label := fmt.Sprintf("#%d %s", id, truncate(name, 48))
		cvss, vector := cvssForClass(class, sev)
		if cvss == "" {
			noCVSS = append(noCVSS, label)
		}
		// A severity-band fallback is honest (its vector field says so) and is not
		// an unparseable vector — do not flag it. Only a real v3.1 vector that
		// fails to compute is a defect worth refusing over.
		if vector != "" && !strings.Contains(vector, "severity band") && cvssScore(vector) < 0 {
			noCVSS = append(noCVSS, label+" (unparseable vector)")
		}
		if remediationFor(class, sev) == "" {
			noRemed = append(noRemed, label)
		}
		// A browser-demonstrable finding owes a screenshot. Injection classes and
		// CSRF are the ones a reader expects to see rendered.
		if shot == "" && browserDemonstrable(class) && status == "confirmed" {
			noEvidence = append(noEvidence, label)
		}
	}
	if err := rows.Err(); err != nil {
		return v, err
	}

	if total == 0 {
		// Nothing to under-deliver on; the report states its own emptiness.
		return v, nil
	}

	if len(noCVSS) > 0 {
		v.Complete = false
		v.Missing = append(v.Missing, fmt.Sprintf(
			"%d of %d findings carry no CVSS v3.1 score: %v", len(noCVSS), total, noCVSS))
	}
	if len(noRemed) > 0 {
		v.Complete = false
		v.Missing = append(v.Missing, fmt.Sprintf(
			"%d of %d findings carry no remediation: %v", len(noRemed), total, noRemed))
	}
	if len(noEvidence) > 0 {
		v.Complete = false
		v.Missing = append(v.Missing, fmt.Sprintf(
			"%d of %d browser-demonstrable findings carry no screenshot evidence: %v",
			len(noEvidence), total, noEvidence))
	}
	// Non-blocking: a failed/blocked run is still reported, but the report must
	// say so rather than read as a clean bill of health.
	var runStatus string
	_ = c.DB.QueryRowContext(ctx, `SELECT COALESCE(status,'') FROM eng_run WHERE id=$1`, runID).Scan(&runStatus)
	if runStatus == "failed" || runStatus == "timeout" || runStatus == "blocked" {
		v.Warnings = append(v.Warnings,
			"run did not complete normally ("+runStatus+"): coverage may be partial")
	}
	if len(noEvidence) == 0 && total > 0 {
		// nothing
	}
	v.Reason = fmt.Sprintf("report withheld: %s", joinSentences(v.Missing))
	return v, nil
}

// loadCVSSProfile reads the operator-set environmental profile for a run's task
// out of eng_run.stats. Returns nil when none has been set — the common state, and
// exactly what the gate refuses on.
func (c *EngagementCollector) loadCVSSProfile(ctx context.Context, runID int64) (*CVSSProfile, error) {
	var statsJSON string
	err := c.DB.QueryRowContext(ctx, `SELECT COALESCE(stats::text,'{}') FROM eng_run WHERE id=$1`, runID).Scan(&statsJSON)
	if err != nil {
		return nil, err
	}
	var stats struct {
		CVSSProfile *CVSSProfile `json:"cvss_profile"`
	}
	if err := json.Unmarshal([]byte(statsJSON), &stats); err != nil {
		return nil, err
	}
	return stats.CVSSProfile, nil
}

// SetCVSSProfile stores the operator's environmental profile on the task's run.
// eng_run is UNIQUE on task_id, so this updates in place and the next report picks
// it up. It rejects a profile that sets a metric with no reason: an unjustified
// rescore is the invented number the gate exists to prevent.
func (c *EngagementCollector) SetCVSSProfile(ctx context.Context, taskID int64, p *CVSSProfile) error {
	if p == nil {
		return fmt.Errorf("profile required")
	}
	for name, m := range map[string]*CVSSMetric{
		"modified_av": p.ModifiedAV, "modified_ac": p.ModifiedAC,
		"modified_pr": p.ModifiedPR, "modified_ui": p.ModifiedUI,
		"modified_s": p.ModifiedS, "modified_c": p.ModifiedC,
		"modified_i": p.ModifiedI, "modified_a": p.ModifiedA,
		"cr": p.CR, "ir": p.IR, "ar": p.AR,
	} {
		if m != nil && strings.TrimSpace(m.Value) != "" && strings.TrimSpace(m.Reason) == "" {
			return fmt.Errorf("metric %s set without a reason: every environmental adjustment must be justified", name)
		}
	}
	if !p.hasAnyReason() && !p.isEmpty() {
		return fmt.Errorf("profile adjusts metrics but carries no rationale")
	}
	blob, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = c.DB.ExecContext(ctx, `
		UPDATE eng_run
		   SET stats = jsonb_set(COALESCE(stats,'{}'::jsonb), '{cvss_profile}', $2::jsonb, true)
		 WHERE task_id=$1`, taskID, string(blob))
	return err
}

// browserDemonstrable reports whether a vulnerability class is the kind a reader
// expects to see executed in a browser, and therefore owes screenshot evidence.
func browserDemonstrable(class string) bool {
	c := strings.ToLower(class)
	for _, kw := range []string{"xss", "cross-site scripting", "csrf", "cross-site request forgery",
		"open redirect", "clickjacking"} {
		if strings.Contains(c, kw) {
			return true
		}
	}
	return false
}

func joinSentences(parts []string) string {
	return strings.Join(parts, "; ")
}

// ReportGateError is returned when a report was requested for a run that has not
// earned one. The caller (HTTP handler) turns it into a clear 409 with the list
// of what is missing, so the operator sees the gap instead of a half-report.
type ReportGateError struct {
	Verdict GateVerdict
}

func (e *ReportGateError) Error() string { return e.Verdict.Reason }
