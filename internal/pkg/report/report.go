package report

import (
	"bytes"
	"context"
	"github.com/aws/aws-sdk-go/service/ecr"
	"k8s.io/klog/v2"
	"kube-ecr-image-scanner/internal/pkg/scanner"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"text/template"
	"time"
)

const (
	keyCvss2Score     = "CVSS2_SCORE"
	keyCvss2Vectors   = "CVSS2_VECTOR"
	keyPackageName    = "package_name"
	keyPackageVersion = "package_version"
	reportTemplate    = `{{ printf "Kubernetes container security updates as of %s\n" .Date }}
{{ printf "----------------------------------------" }}
{{- range .Reports }}
{{ .ImageUri | printf "Image: %s" }}
{{ printf "Summary:\n" }}
{{- if index .SeverityCounts "CRITICAL" }}{{      printf "%15s%5d\n" "CRITICAL: "      (index .SeverityCounts "CRITICAL")      }}{{ end }}
{{- if index .SeverityCounts "HIGH" }}{{          printf "%15s%5d\n" "HIGH: "          (index .SeverityCounts "HIGH")          }}{{ end }}
{{- if index .SeverityCounts "MEDIUM" }}{{        printf "%15s%5d\n" "MEDIUM: "        (index .SeverityCounts "MEDIUM")        }}{{ end }}
{{- if index .SeverityCounts "LOW" }}{{           printf "%15s%5d\n" "LOW: "           (index .SeverityCounts "LOW")           }}{{ end }}
{{- if index .SeverityCounts "INFORMATIONAL" }}{{ printf "%15s%5d\n" "INFORMATIONAL: " (index .SeverityCounts "INFORMATIONAL") }}{{ end }}
{{- if index .SeverityCounts "UNDEFINED" }}{{     printf "%15s%5d\n" "UNDEFINED: "     (index .SeverityCounts "UNDEFINED")     }}{{ end }}
{{ printf "Reporting Threshold: %s\n" .SeverityThreshold }}
{{ printf "Details:\n" }}
{{- $printedVulns := false -}}
{{- $severityThreshold := .SeverityThreshold -}}
{{- range .Vulnerabilities -}}
{{- if le (severityToRank $severityThreshold) (severityToRank .Severity) -}}
{{- $printedVulns = true }}
{{ printf "%s: %s (%s)" .Severity .Name .Uri | printf "%-s" }}
{{ printf "Package: %s:%s" .PackageName .PackageVersion | printf "%-s\n" }}
{{- if .Score }}{{ printf "CVSS2 Score: %.1f" .Score | printf "%-s\n" }}{{ end -}}
{{- if .Vectors }}{{ printf "CVSS2 Vectors: %s" .Vectors | printf "%-s\n"}}{{ end -}}
{{ .Description | printf "Description: %s" | printf "%-s\n" }}
{{- end -}}
{{- end -}}
{{- if not $printedVulns }}{{ printf "No vulnerabilities at %s or above detected!" .SeverityThreshold | printf "%-s" }}{{ end }}
{{ printf "----------------------------------------" }}
{{ end -}}
`
)

type ImageReport struct {
	ImageUri          string
	Vulnerabilities   []*Vulnerability
	SeverityCounts    map[string]int64
	SeverityThreshold string
}

type Report struct {
	Date    string
	Reports []*ImageReport
}

type Vulnerability struct {
	PackageName    string
	PackageVersion string
	Score          float64
	Description    string
	Name           string
	Severity       string
	Uri            *url.URL
	Vectors        string
}

// Build creates a report of all vulnerability scans in the given scans channel.
func Build(ctx context.Context, threshold string, concurrency int, scans chan *scanner.ImageScanResult) []*ImageReport {
	klog.Info("Building vulnerability report")
	close(scans)

	// Configure image report generators and reports channel
	reportsCh := make(chan *ImageReport, len(scans))
	wg := &sync.WaitGroup{}
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go generateImageReport(ctx, wg, threshold ,scans, reportsCh)
	}
	wg.Wait()

	// Read all ImageReports into a slice for sorting
	close(reportsCh)
	var reports []*ImageReport
	for report := range reportsCh {
		reports = append(reports, report)
	}

	// Sort reportsCh by ImageUri (asc)
	klog.Infof("Sorting %d Reports", len(reports))
	sort.Slice(reports, func(i, j int) bool {
		return reports[i].ImageUri < reports[j].ImageUri
	})

	return reports
}

// Export creates the aggregate vulnerability report from the individual image vulnerability reports.
func Export(reports []*ImageReport) (*string, error) {
	report := &Report{
		time.Now().Format(time.RFC1123Z),
		reports,
	}

	klog.Info("Generating template")
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"severityToRank": func(severity string) int {
			return severityToRank(severity)
		},
	}).Parse(reportTemplate)
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	err = tmpl.Execute(&buffer, report)
	if err != nil {
		return nil, err
	}
	reportStr := buffer.String()
	return &reportStr, nil
}

// generateImageReport generates a vulnerability report for each raw image scan result present in the given
// results channel; can safely be called concurrently.
func generateImageReport(ctx context.Context, wg *sync.WaitGroup, threshold string, scans <-chan *scanner.ImageScanResult, reports chan *ImageReport) {
	defer wg.Done()
	for {
		select {
		// Handle scans received from the scans channel
		case scan, ok := <-scans:
			// End this worker if the channel is closed and there are no more items in the channel
			if !ok {
				return
			}

			// Dereference the pointers in the FindingSeverityCounts map, so they can be printed in the report template
			// for this image
			report := &ImageReport{
				ImageUri:          *scan.Image,
				SeverityCounts:    make(map[string]int64, len(scan.Findings.FindingSeverityCounts)),
				SeverityThreshold: threshold,
			}
			for k, v := range scan.Findings.FindingSeverityCounts {
				report.SeverityCounts[k] = *v
			}

			// Parse the image scan findings into a printable format
			if scan.Findings != nil {
				for _, v := range scan.Findings.Findings {
					vuln := parseFindings(v)
					report.Vulnerabilities = append(report.Vulnerabilities, vuln)
				}
			}
			// Sort report.Vulnerabilities; first by Severity (desc), then by Score (desc)
			klog.Infof("Sorting %d vulnerabilities", len(report.Vulnerabilities))
			sort.Slice(report.Vulnerabilities, func(i, j int) bool {
				if severityToRank(report.Vulnerabilities[i].Severity) > severityToRank(report.Vulnerabilities[j].Severity) {
					return true
				}
				if severityToRank(report.Vulnerabilities[i].Severity) < severityToRank(report.Vulnerabilities[j].Severity) {
					return false
				}
				return report.Vulnerabilities[i].Score > report.Vulnerabilities[j].Score
			})
			reports <- report
		// Handle Context cancellation
		case <-ctx.Done():
			klog.Info("Received cancellation signal, stopping image report generator...")
			return
		}
	}
}

// parseFindings extracts the vulnerability data from the ImageScanFinding struct returned from ECR.
func parseFindings(finding *ecr.ImageScanFinding) *Vulnerability {
	vAttrs := make(map[string]string, len(finding.Attributes))
	for _, a := range finding.Attributes {
		vAttrs[*a.Key] = *a.Value
	}
	// Extract basic vulnerability info
	vuln := &Vulnerability{
		Description:    *finding.Description,
		Name:           *finding.Name,
		PackageName:    vAttrs[keyPackageName],
		PackageVersion: vAttrs[keyPackageVersion],
		Severity:       *finding.Severity,
		Vectors:        vAttrs[keyCvss2Vectors],
	}
	// If a CVSS2_SCORE attribute is set, parse it and set the score on the vulnerability
	if score, ok := vAttrs[keyCvss2Score]; ok {
		s, err := strconv.ParseFloat(score, 64)
		if err == nil {
			vuln.Score = s
		}
	}
	// Parse the vulnerability URI
	u, err := url.Parse(*finding.Uri)
	if err == nil {
		vuln.Uri = u
	}
	return vuln
}

// severityToRank returns a rank for a given severity string.
func severityToRank(severity string) int {
	switch severity {
	case ecr.FindingSeverityInformational:
		return 1
	case ecr.FindingSeverityLow:
		return 2
	case ecr.FindingSeverityMedium:
		return 5
	case ecr.FindingSeverityHigh:
		return 10
	case ecr.FindingSeverityCritical:
		return 100
	case ecr.FindingSeverityUndefined:
		return 0
	default:
		return -1
	}
}
