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

const (
	reportHeaderTemplate = `
{{ .ImageUri | printf "Container image security digest: %s" }}
{{ printf "Summary:\n" }}
{{- if index .SeverityCounts "CRITICAL" }}{{      printf "*%-s*: *%d*\n" "CRITICAL"      (index .SeverityCounts "CRITICAL")      }}{{ end }}
{{- if index .SeverityCounts "HIGH" }}{{          printf "*%-s*: *%d*\n" "HIGH"          (index .SeverityCounts "HIGH")          }}{{ end }}
{{- if index .SeverityCounts "MEDIUM" }}{{        printf "*%-s*: *%d*\n" "MEDIUM"        (index .SeverityCounts "MEDIUM")        }}{{ end }}
{{- if index .SeverityCounts "LOW" }}{{           printf "*%-s*: *%d*\n" "LOW"           (index .SeverityCounts "LOW")           }}{{ end }}
{{- if index .SeverityCounts "INFORMATIONAL" }}{{ printf "*%-s*: *%d*\n" "INFORMATIONAL" (index .SeverityCounts "INFORMATIONAL") }}{{ end }}
{{- if index .SeverityCounts "UNDEFINED" }}{{     printf "*%-s*: *%d*\n" "UNDEFINED"     (index .SeverityCounts "UNDEFINED")     }}{{ end }}
{{ printf "Reporting Threshold: *%s*\n" .SeverityThreshold }}
{{ printf "Details:\n" }}
`
	reportVulnerabilityTemplate = `{{ printf "*%s*: <%s|%s>" .Severity .Uri .Name | printf "%-s" }}
{{ printf "*Package*: %s:%s" .PackageName .PackageVersion | printf "%-s\n" }}
{{- if .Score }}{{ printf "*CVSS2 Score*: %.1f" .Score | printf "%-s\n" }}{{ end -}}
{{- if .Vectors }}{{ printf "*CVSS2 Vectors*: %s" .Vectors | printf "%-s\n"}}{{ end -}}
{{ .Description | printf "*Description*: %s" | printf "%-s\n" }}`
)

// SlackReport generates vulnerability reports suitable for display within a Slack message by implementing
// the Exporter interface.
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

// Export posts vulnerability reports for each image to Slack as a message composed of slack.Block objects.
func (sr *SlackReport) Export(reports []*ImageReport) error {
	if len(reports) > 0 {
		channelID, timestamp, err := sr.postMessage(slack.MsgOptionBlocks(sr.generateTextBlock(
			fmt.Sprintf("Kubernetes container security updates as of *%s*", time.Now().Format(time.RFC1123Z)))))
		if err != nil {
			return err
		}
		klog.Infof("Message successfully sent to channel %s at %s", channelID, timestamp)
	}
	for _, r := range reports {
		header, err := sr.buildReportHeader(r)
		if err != nil {
			return err
		}
		blockParts := []slack.Block{header}

		vulns, err := sr.buildReportVulnerabilities(r)
		if err != nil {
			return err
		}
		blockParts = append(blockParts, vulns...)

		channelID, timestamp, err := sr.postMessage(slack.MsgOptionBlocks(blockParts...))
		if err != nil {
			return err
		}
		klog.Infof("Message successfully sent to channel %s at %s", channelID, timestamp)
	}
	return nil
}

// buildReportHeader constructs the header block for the given image vulnerability report.
func (sr *SlackReport) buildReportHeader(report *ImageReport) (slack.Block, error) {
	klog.Infof("Generating report for image %s...", report.ImageUri)
	tmpl, err := template.New("report header").Funcs(template.FuncMap{
		"severityToRank": func(severity string) int {
			return severityToRank(severity)
		},
	}).Parse(reportHeaderTemplate)
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	if err := tmpl.Execute(&buffer, report); err != nil {
		return nil, err
	}
	msg := buffer.String()
	blk := sr.generateTextBlock(msg)
	return blk, err
}

func (sr *SlackReport) buildReportVulnerabilities(report *ImageReport) ([]slack.Block, error) {
	klog.Infof("Generating report details for image %s...", report.ImageUri)
	tmpl, err := template.New("report vulnerability").Parse(reportVulnerabilityTemplate)
	if err != nil {
		return nil, err
	}
	blocks := make([]slack.Block, 0)
	for _, v := range report.Vulnerabilities {
		if severityToRank(v.Severity) > severityToRank(report.SeverityThreshold) {
			var buffer bytes.Buffer
			if err := tmpl.Execute(&buffer, v); err != nil {
				return nil, err
			}
			blocks = append(blocks, sr.generateTextBlock(buffer.String()))
			// Ensure at most 50 blocks are present on a single message, including the report header and separator blocks
			if len(blocks) == 48 {
				break
			}
		}
	}
	if len(blocks) == 0 {
		blocks = append(blocks, sr.generateTextBlock(fmt.Sprintf("No vulnerabilities at %s or above detected!", report.SeverityThreshold)))
	}
	blocks = append(blocks, slack.NewDividerBlock())
	return blocks, nil
}

// generateTextBlock returns a slack SectionBlock for the given input string.
func (sr *SlackReport) generateTextBlock(input string) slack.Block {
	// Ensure block text is within Slack api limits
	if len(input) > 3000 {
		input = input[:2985] + "...\n<TRUNCATED>"
	}
	b := slack.NewTextBlockObject("mrkdwn", input, false, false)
	return slack.NewSectionBlock(b, nil, nil)
}

// postMessage sends the given slack.MsgOption messages to the Slack channel configured for this report.
func (sr *SlackReport) postMessage(options ...slack.MsgOption) (string, string, error) {
	// Delay calls to client.postMessage in order to avoid exceeding Slack's rate limit
	time.Sleep(1 * time.Second)
	return sr.client.PostMessage(sr.channel, options...)
}
