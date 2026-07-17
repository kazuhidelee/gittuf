// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package compression

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

var errUnauthorized = errors.New("principal is not authorized for target version")

type options struct {
	baseFile         string
	targetFile       string
	principal        string
	path             string
	basePrincipals   string
	targetPrincipals string
	outDir           string
}

type manifest struct {
	Path              string   `json:"path"`
	TargetSHA256      string   `json:"targetSHA256"`
	FullArtifactFile  string   `json:"fullArtifactFile"`
	DeltaArtifactFile string   `json:"deltaArtifactFile,omitempty"`
	TargetPrincipals  []string `json:"targetPrincipals"`
	DeltaPrincipals   []string `json:"deltaPrincipals,omitempty"`
}

type delta struct {
	PrefixLen   int    `json:"prefixLen"`
	SuffixLen   int    `json:"suffixLen"`
	Replacement []byte `json:"replacement"`
}

type bundle struct {
	manifest        manifest
	fullCiphertext  []byte
	fullKey         []byte
	deltaCiphertext []byte
	deltaKey        []byte
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.baseFile, "base-file", "", "Path to the previous plaintext version")
	cmd.Flags().StringVar(&o.targetFile, "target-file", "", "Path to the target plaintext version")
	cmd.Flags().StringVar(&o.principal, "principal", "", "Principal to simulate")
	cmd.Flags().StringVar(&o.path, "path", "", "Logical protected path for the manifest")
	cmd.Flags().StringVar(&o.basePrincipals, "base-principals", "", "Comma-separated principal IDs allowed to read the base version")
	cmd.Flags().StringVar(&o.targetPrincipals, "target-principals", "", "Comma-separated principal IDs allowed to read the target version")
	cmd.Flags().StringVar(&o.outDir, "out-dir", "", "Optional directory to write demo artifacts into")
	cmd.MarkFlagRequired("target-file")       //nolint:errcheck
	cmd.MarkFlagRequired("principal")         //nolint:errcheck
	cmd.MarkFlagRequired("target-principals") //nolint:errcheck
}

func (o *options) Run(_ *cobra.Command, _ []string) error {
	targetBytes, err := os.ReadFile(o.targetFile)
	if err != nil {
		return err
	}

	var baseBytes []byte
	if o.baseFile != "" {
		baseBytes, err = os.ReadFile(o.baseFile)
		if err != nil {
			return err
		}
	}

	targetPrincipals := normalizePrincipals(o.targetPrincipals)
	basePrincipals := normalizePrincipals(o.basePrincipals)
	if o.path == "" {
		o.path = o.targetFile
	}

	b, err := buildBundle(o.path, baseBytes, targetBytes, basePrincipals, targetPrincipals)
	if err != nil {
		return err
	}

	reconstructed, mode, err := reconstructForPrincipal(b, o.principal, baseBytes)
	if err != nil {
		return err
	}

	if sha256Hex(reconstructed) != b.manifest.TargetSHA256 {
		return errors.New("reconstructed bytes failed integrity check")
	}

	if o.outDir != "" {
		if err := writeBundle(o.outDir, b); err != nil {
			return err
		}
	}

	fmt.Printf("mode=%s path=%s sha256=%s\n", mode, b.manifest.Path, b.manifest.TargetSHA256)
	return nil
}

func New() *cobra.Command {
	o := options{}
	cmd := &cobra.Command{
		Use:               "demo",
		Short:             "Build and verify a tiny encrypted snapshot/delta demo",
		DisableAutoGenTag: true,
		RunE:              o.Run,
	}
	o.AddFlags(cmd)
	return cmd
}

func buildBundle(path string, baseBytes, targetBytes []byte, basePrincipals, targetPrincipals []string) (*bundle, error) {
	fullPayload, err := gzipBytes(targetBytes)
	if err != nil {
		return nil, err
	}
	fullKey, fullCiphertext, err := encrypt(fullPayload)
	if err != nil {
		return nil, err
	}

	b := &bundle{
		manifest: manifest{
			Path:             path,
			TargetSHA256:     sha256Hex(targetBytes),
			FullArtifactFile: "full.enc",
			TargetPrincipals: append([]string(nil), targetPrincipals...),
		},
		fullCiphertext: fullCiphertext,
		fullKey:        fullKey,
	}

	if len(baseBytes) == 0 {
		return b, nil
	}

	deltaBytes, err := json.Marshal(makeDelta(baseBytes, targetBytes))
	if err != nil {
		return nil, err
	}
	compressedDelta, err := gzipBytes(deltaBytes)
	if err != nil {
		return nil, err
	}

	deltaKey, deltaCiphertext, err := encrypt(compressedDelta)
	if err != nil {
		return nil, err
	}
	b.manifest.DeltaArtifactFile = "delta.enc"
	if len(basePrincipals) == 0 {
		b.manifest.DeltaPrincipals = append([]string(nil), targetPrincipals...)
	} else {
		b.manifest.DeltaPrincipals = intersectPrincipals(basePrincipals, targetPrincipals)
	}
	b.deltaCiphertext = deltaCiphertext
	b.deltaKey = deltaKey
	return b, nil
}

func reconstructForPrincipal(b *bundle, principal string, baseBytes []byte) ([]byte, string, error) {
	if !contains(b.manifest.TargetPrincipals, principal) {
		return nil, "", errUnauthorized
	}

	if b.manifest.DeltaArtifactFile != "" && contains(b.manifest.DeltaPrincipals, principal) && len(baseBytes) != 0 {
		plaintextDelta, err := decrypt(b.deltaCiphertext, b.deltaKey)
		if err != nil {
			return nil, "", err
		}
		plaintextDelta, err = gunzipBytes(plaintextDelta)
		if err != nil {
			return nil, "", err
		}
		d := delta{}
		if err := json.Unmarshal(plaintextDelta, &d); err != nil {
			return nil, "", err
		}
		return applyDelta(baseBytes, d)
	}

	plaintextFull, err := decrypt(b.fullCiphertext, b.fullKey)
	if err != nil {
		return nil, "", err
	}
	plaintextFull, err = gunzipBytes(plaintextFull)
	if err != nil {
		return nil, "", err
	}
	return plaintextFull, "full", nil
}

func writeBundle(outDir string, b *bundle) error {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return err
	}

	manifestBytes, err := json.MarshalIndent(b.manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "manifest.json"), manifestBytes, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, b.manifest.FullArtifactFile), b.fullCiphertext, 0o600); err != nil {
		return err
	}
	if b.manifest.DeltaArtifactFile != "" {
		if err := os.WriteFile(filepath.Join(outDir, b.manifest.DeltaArtifactFile), b.deltaCiphertext, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func makeDelta(baseBytes, targetBytes []byte) delta {
	prefixLen := 0
	limit := min(len(baseBytes), len(targetBytes))
	for prefixLen < limit && baseBytes[prefixLen] == targetBytes[prefixLen] {
		prefixLen++
	}

	baseTail := len(baseBytes) - prefixLen
	targetTail := len(targetBytes) - prefixLen
	suffixLen := 0
	for suffixLen < baseTail && suffixLen < targetTail &&
		baseBytes[len(baseBytes)-1-suffixLen] == targetBytes[len(targetBytes)-1-suffixLen] {
		suffixLen++
	}

	return delta{
		PrefixLen:   prefixLen,
		SuffixLen:   suffixLen,
		Replacement: append([]byte(nil), targetBytes[prefixLen:len(targetBytes)-suffixLen]...),
	}
}

func applyDelta(baseBytes []byte, d delta) ([]byte, string, error) {
	if d.PrefixLen < 0 || d.SuffixLen < 0 || d.PrefixLen+d.SuffixLen > len(baseBytes) {
		return nil, "", errors.New("invalid delta")
	}

	out := make([]byte, 0, d.PrefixLen+len(d.Replacement)+d.SuffixLen)
	out = append(out, baseBytes[:d.PrefixLen]...)
	out = append(out, d.Replacement...)
	out = append(out, baseBytes[len(baseBytes)-d.SuffixLen:]...)
	return out, "delta", nil
}

func encrypt(plaintext []byte) ([]byte, []byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return key, gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, data := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, data, nil)
}

func gzipBytes(data []byte) ([]byte, error) {
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func gunzipBytes(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func normalizePrincipals(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	principals := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		principals = append(principals, part)
	}
	slices.Sort(principals)
	return principals
}

func intersectPrincipals(a, b []string) []string {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(a))
	for _, item := range a {
		set[item] = struct{}{}
	}
	out := make([]string, 0, min(len(a), len(b)))
	for _, item := range b {
		if _, ok := set[item]; ok {
			out = append(out, item)
		}
	}
	return out
}

func contains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}
