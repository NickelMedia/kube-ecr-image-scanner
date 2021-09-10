package report

import "net/url"

type Exporter interface {
	Export(reports []*ImageReport) error
}

type ImageReport struct {
	ImageUri          string
	Vulnerabilities   []*Vulnerability
	SeverityCounts    map[string]int64
	SeverityThreshold string
	Err               error
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
