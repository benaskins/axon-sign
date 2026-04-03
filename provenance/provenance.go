package provenance

import (
	"bytes"
	"fmt"
	"os"
	"text/template"
	"time"
)

// ProvenanceRecord holds the data needed to generate a PROVENANCE.md document.
type ProvenanceRecord struct {
	Signer         string
	KeyFingerprint string
	SignedAt       time.Time
	ArtifactHash   string
	ArtifactPath   string
	Signature      string
	RotatedKeys    []string
}

var provenanceTemplate = template.Must(template.New("provenance").Parse(`# PROVENANCE

## Artifact

| Field       | Value |
|-------------|-------|
| Path        | {{ .ArtifactPath }} |
| SHA-256     | {{ .ArtifactHash }} |

## Signature

| Field           | Value |
|-----------------|-------|
| Signer          | {{ .Signer }} |
| Key Fingerprint | {{ .KeyFingerprint }} |
| Signed At       | {{ .SignedAt.UTC.Format "2006-01-02T15:04:05Z" }} |
| Signature       | {{ .Signature }} |
{{ if .RotatedKeys }}
## Previously Rotated Keys

{{ range .RotatedKeys }}- {{ . }}
{{ end }}{{ end }}`))

// GenerateProvenance renders a Markdown provenance document from r.
// Returns an error if any required field is empty.
func GenerateProvenance(r ProvenanceRecord) ([]byte, error) {
	if err := validate(r); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := provenanceTemplate.Execute(&buf, r); err != nil {
		return nil, fmt.Errorf("provenance: render template: %w", err)
	}
	return buf.Bytes(), nil
}

// WriteProvenance generates a provenance document and writes it to dest.
func WriteProvenance(r ProvenanceRecord, dest string) error {
	data, err := GenerateProvenance(r)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		return fmt.Errorf("provenance: write file: %w", err)
	}
	return nil
}

func validate(r ProvenanceRecord) error {
	switch {
	case r.Signer == "":
		return fmt.Errorf("provenance: Signer is required")
	case r.KeyFingerprint == "":
		return fmt.Errorf("provenance: KeyFingerprint is required")
	case r.ArtifactHash == "":
		return fmt.Errorf("provenance: ArtifactHash is required")
	case r.ArtifactPath == "":
		return fmt.Errorf("provenance: ArtifactPath is required")
	case r.Signature == "":
		return fmt.Errorf("provenance: Signature is required")
	}
	return nil
}
