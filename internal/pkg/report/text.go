package report

import (
	"bytes"
	"k8s.io/klog/v2"
	"text/template"
	"time"
)

const reportTemplate = `{{ printf "Kubernetes container security updates as of %s\n" .Date }}
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

// TextReport produces text-based vulnerability reports by implementing the ExportFormatter interface.
type TextReport struct{}

// Export simply logs the text-based reports to standard output at the INFO level.
func (tr *TextReport) Export(reports []*string) error {
	for _, s := range reports {
		klog.Infof("GENERATED REPORT:\n%s", *s)
	}
	return nil
}

// Format converts the raw reports to a text-based format, suitable for logging.
func (tr *TextReport) Format(reports []*ImageReport) ([]*string, error) {
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
	return []*string{&reportStr}, nil
}
