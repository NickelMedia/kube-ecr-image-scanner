package report

import (
	"bytes"
	"k8s.io/klog/v2"
	"text/template"
	"time"
)

const textReportTemplate = `{{ printf "Kubernetes container security updates as of %s\n" .Date }}
{{ printf "----------------------------------------" }}
{{- range .Reports }}
{{ .ImageUri | printf "Image: %s" }}
{{ if eq .Err nil -}}
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
{{ else -}}
{{ printf "Error: %s" .Err }}
{{ end -}}
{{ printf "----------------------------------------" }}
{{ end -}}
`

// TextReport produces text-based vulnerability reports by implementing the Exporter interface.
type TextReport struct{}

// Export converts the reports to a text-based format and logs them to standard output at the INFO level.
func (tr *TextReport) Export(reports []*ImageReport) error {
	report := &Report{
		time.Now().Format(time.RFC1123Z),
		reports,
	}

	klog.Info("Generating template")
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"severityToRank": func(severity string) int {
			return severityToRank(severity)
		},
	}).Parse(textReportTemplate)
	if err != nil {
		return err
	}
	var buffer bytes.Buffer
	err = tmpl.Execute(&buffer, report)
	if err != nil {
		return err
	}
	reportStr := buffer.String()
	klog.Infof("GENERATED REPORT:\n%s", reportStr)
	return nil
}
