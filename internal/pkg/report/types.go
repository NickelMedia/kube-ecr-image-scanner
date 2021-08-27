package report

import "net/url"

type ExportFormatter interface {
	Export(reports []*string) error
	Format(reports []*ImageReport) ([]*string, error)
}

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
