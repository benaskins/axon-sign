package provenance_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/benaskins/axon-sign/provenance"
)

func TestGenerateProvenance_ContainsAllFields(t *testing.T) {
	r := provenance.ProvenanceRecord{
		Signer:        "Alice Example",
		KeyFingerprint: "SHA256:abc123def456",
		SignedAt:      time.Date(2026, 4, 3, 12, 0, 0, 0, time.UTC),
		ArtifactHash:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		ArtifactPath:  "dist/myapp-v1.0.tar.gz",
		Signature:     "AAABBBCCC",
		RotatedKeys:   []string{"SHA256:old1", "SHA256:old2"},
	}

	out, err := provenance.GenerateProvenance(r)
	if err != nil {
		t.Fatalf("GenerateProvenance failed: %v", err)
	}

	content := string(out)

	checks := []struct {
		label string
		want  string
	}{
		{"Signer", r.Signer},
		{"KeyFingerprint", r.KeyFingerprint},
		{"SignedAt", "2026-04-03"},
		{"ArtifactHash", r.ArtifactHash},
		{"ArtifactPath", r.ArtifactPath},
		{"Signature", r.Signature},
		{"RotatedKey[0]", r.RotatedKeys[0]},
		{"RotatedKey[1]", r.RotatedKeys[1]},
	}

	for _, c := range checks {
		if !strings.Contains(content, c.want) {
			t.Errorf("expected output to contain %s (%q), got:\n%s", c.label, c.want, content)
		}
	}
}

func TestGenerateProvenance_NoRotatedKeys(t *testing.T) {
	r := provenance.ProvenanceRecord{
		Signer:        "Bob",
		KeyFingerprint: "SHA256:xyz",
		SignedAt:      time.Now(),
		ArtifactHash:  "deadbeef",
		ArtifactPath:  "file.txt",
		Signature:     "SIG",
	}

	out, err := provenance.GenerateProvenance(r)
	if err != nil {
		t.Fatalf("GenerateProvenance failed: %v", err)
	}

	if len(out) == 0 {
		t.Error("expected non-empty output")
	}
}

func TestGenerateProvenance_MissingRequiredFields(t *testing.T) {
	cases := []struct {
		name string
		r    provenance.ProvenanceRecord
	}{
		{"missing Signer", provenance.ProvenanceRecord{
			KeyFingerprint: "SHA256:abc",
			SignedAt:      time.Now(),
			ArtifactHash:  "hash",
			ArtifactPath:  "path",
			Signature:     "sig",
		}},
		{"missing KeyFingerprint", provenance.ProvenanceRecord{
			Signer:       "Alice",
			SignedAt:     time.Now(),
			ArtifactHash: "hash",
			ArtifactPath: "path",
			Signature:    "sig",
		}},
		{"missing ArtifactHash", provenance.ProvenanceRecord{
			Signer:         "Alice",
			KeyFingerprint: "SHA256:abc",
			SignedAt:       time.Now(),
			ArtifactPath:   "path",
			Signature:      "sig",
		}},
		{"missing ArtifactPath", provenance.ProvenanceRecord{
			Signer:         "Alice",
			KeyFingerprint: "SHA256:abc",
			SignedAt:       time.Now(),
			ArtifactHash:   "hash",
			Signature:      "sig",
		}},
		{"missing Signature", provenance.ProvenanceRecord{
			Signer:         "Alice",
			KeyFingerprint: "SHA256:abc",
			SignedAt:       time.Now(),
			ArtifactHash:   "hash",
			ArtifactPath:   "path",
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := provenance.GenerateProvenance(tc.r)
			if err == nil {
				t.Error("expected error for missing required field, got nil")
			}
		})
	}
}

func TestWriteProvenance(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "PROVENANCE.md")

	r := provenance.ProvenanceRecord{
		Signer:        "Carol",
		KeyFingerprint: "SHA256:fff",
		SignedAt:      time.Now(),
		ArtifactHash:  "cafebabe",
		ArtifactPath:  "artifact.bin",
		Signature:     "MYSIG",
	}

	if err := provenance.WriteProvenance(r, dest); err != nil {
		t.Fatalf("WriteProvenance failed: %v", err)
	}

	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("could not read written file: %v", err)
	}

	if !strings.Contains(string(data), "Carol") {
		t.Error("expected written file to contain signer name")
	}
}
