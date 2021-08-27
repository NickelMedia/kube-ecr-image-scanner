package report

import (
	"bytes"
	"fmt"
	"github.com/slack-go/slack"
	"k8s.io/klog/v2"
	"kube-ecr-image-scanner/cmd"
	"text/template"
	"time"
)

const slackReportTemplate = `
{{ .ImageUri | printf "Container image security digest: %s" }}
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
`

// SlackReport generates vulnerability reports suitable for display within a Slack message by implementing
// the ExportFormatter interface.
type SlackReport struct{
	client  *slack.Client
	channel string
}

// NewSlackReport returns a new SlackReport using the given cmd.SlackConfig.
func NewSlackReport(cfg *cmd.SlackConfig) *SlackReport {
	return &SlackReport{
		slack.New(cfg.Token),
		cfg.ChannelID,
	}
}

// Export posts vulnerability reports for each image to Slack as a slack.Message composed of slack.Block objects.
func (sr *SlackReport) Export(reportMsgs []*string) error {
	headerSection := sr.GenerateTextBlock(fmt.Sprintf("Kubernetes container security updates as of %s\n", time.Now().Format(time.RFC1123Z)))
	for _, msg := range reportMsgs {
		reportSection := sr.GenerateTextBlock(*msg)
		blockParts := []slack.Block{
			headerSection,
			reportSection,
			slack.NewDividerBlock(),
		}
		channelID, timestamp, err := sr.PostMessage(blockParts...)
		if err != nil {
			return err
		}
		klog.Infof("Message successfully sent to channel %s at %s", channelID, timestamp)
	}
	return nil
}

// Format parses each ImageReport into a string suitable for use within a slack.Block.
func (sr *SlackReport) Format(reports []*ImageReport) ([]*string, error) {
	klog.Info("Generating slack message template")
	tmpl, err := template.New("slack").Funcs(template.FuncMap{
		"severityToRank": func(severity string) int {
			return severityToRank(severity)
		},
	}).Parse(slackReportTemplate)

	if err != nil {
		return nil, err
	}

	reportMsgs := make([]*string, len(reports))
	for i, r := range reports {
		reportMsgs[i], err = sr.BuildReportMessage(tmpl, r)
		if err != nil {
			return nil, err
		}
	}

	return reportMsgs, nil
}

// BuildReportMessage constructs the message body for the given image vulnerability report.
func (sr *SlackReport) BuildReportMessage(tmpl *template.Template, report *ImageReport) (*string, error) {
	var buffer bytes.Buffer
	err := tmpl.Execute(&buffer, report)
	msg := buffer.String()
	return &msg, err
}

// GenerateTextBlock returns a slack SectionBlock for the given input string.
func (sr *SlackReport) GenerateTextBlock(input string) slack.Block {
	b := slack.NewTextBlockObject("mrkdwn", input, false, false)
	return slack.NewSectionBlock(b, nil, nil)
}

// BlockMessage returns a single slack.Message for multiple slack.Block inputs.
func (sr *SlackReport) BlockMessage(blocks ...slack.Block) slack.Message {
	return slack.NewBlockMessage(blocks...)
}

// PostMessage sends the given slack.Block messages to the Slack channel configured for this report.
func (sr *SlackReport) PostMessage(blocks ...slack.Block) (string, string, error) {
	// Delay calls to client.PostMessage in order to avoid exceeding Slack's rate limit
	time.Sleep(1 * time.Second)
	return sr.client.PostMessage(sr.channel, slack.MsgOptionBlocks(blocks...))
}
