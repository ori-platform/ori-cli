// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/ori-platform/ori-cli/internal/binding"
	"github.com/ori-platform/ori-cli/internal/output"
	"github.com/spf13/cobra"
)

// Reading limits. A binding is kilobytes and a key is under one; a path that
// names something larger is not either of them.
const (
	documentReadLimit = 1 << 20
	keyReadLimit      = 16 << 10
)

// signOptions is everything the sign command was told. A field signing owns is
// carried with whether its flag was given, so an explicit empty value is
// refused rather than read as absent.
type signOptions struct {
	in           string
	keyPath      string
	keyFD        int
	keyFDGiven   bool
	controlPaths []string
	signerID     ownedFlag
	actor        ownedFlag
	reason       ownedFlag
	out          string
	force        bool
}

type ownedFlag struct {
	value string
	given bool
}

func newBindingSignCommand(state *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign an assembled binding into the envelope deliver accepts",
		Long: `Sign a binding document with the commissioning key and write the
envelope the runtime accepts at deliver.

The document is the draft capture wrote, with the control leg export assembled
attached through --control-path, or a complete document being signed again.
What signing owns — issued_at_ms, signer_id, signing_key, actor and reason — is
filled where the document left it absent and never rewritten where it did not:
a flag that disagrees with the document is refused, and so is a document that
names a signing_key other than the one this key derives.

The key is read from a file only this user can read, or from an inherited
descriptor. It is never taken from a flag value or the environment, because
both are visible to every process on the machine.

Nothing here reaches the runtime. The document is checked as a consumer would
check it before it is signed, the envelope is verified after, and the verdict
reported names what an offline check proves and what only delivery decides.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var opts signOptions
			var err error
			if opts.in, err = cmd.Flags().GetString("in"); err != nil {
				return fmt.Errorf("failed to read --in: %w", err)
			}
			if opts.keyPath, err = cmd.Flags().GetString("key"); err != nil {
				return fmt.Errorf("failed to read --key: %w", err)
			}
			if opts.keyFD, err = cmd.Flags().GetInt("key-fd"); err != nil {
				return fmt.Errorf("failed to read --key-fd: %w", err)
			}
			opts.keyFDGiven = cmd.Flags().Changed("key-fd")
			if opts.controlPaths, err = cmd.Flags().GetStringArray("control-path"); err != nil {
				return fmt.Errorf("failed to read --control-path: %w", err)
			}
			for name, target := range map[string]*ownedFlag{
				"signer-id": &opts.signerID, "actor": &opts.actor, "reason": &opts.reason,
			} {
				if target.value, err = cmd.Flags().GetString(name); err != nil {
					return fmt.Errorf("failed to read --%s: %w", name, err)
				}
				target.given = cmd.Flags().Changed(name)
			}
			if opts.out, err = cmd.Flags().GetString("out"); err != nil {
				return fmt.Errorf("failed to read --out: %w", err)
			}
			if opts.force, err = cmd.Flags().GetBool("force"); err != nil {
				return fmt.Errorf("failed to read --force: %w", err)
			}
			return runBindingSign(state, cmd.InOrStdin(), opts)
		},
	}
	cmd.Flags().String("in", "", "the document to sign, or - for stdin")
	cmd.Flags().String("key", "", "file holding the commissioning private key")
	cmd.Flags().Int("key-fd", 0, "inherited descriptor holding the commissioning private key")
	cmd.Flags().StringArray("control-path", nil,
		"attach an exported control leg to a zone, as zone=file (repeatable)")
	cmd.Flags().String("signer-id", "", "the signer_id to record, when the document has none")
	cmd.Flags().String("actor", "", "the actor to record, when the document has none")
	cmd.Flags().String("reason", "", "the reason to record, when the document has none")
	cmd.Flags().String("out", "", "write the envelope here instead of stdout")
	cmd.Flags().Bool("force", false, "overwrite an existing envelope")
	_ = cmd.MarkFlagRequired("in")
	return cmd
}

// runBindingSign assembles, checks, signs, verifies and only then writes.
func runBindingSign(state *rootState, stdin io.Reader, opts signOptions) error {
	if (opts.keyPath == "") == !opts.keyFDGiven {
		return errors.New("exactly one of --key or --key-fd names where the key is read from")
	}
	if opts.in == "-" && opts.keyFDGiven && opts.keyFD == 0 {
		return errors.New("--in - and --key-fd 0 would both read stdin")
	}
	// Checked before anything is read, so the refusal is not the last thing
	// an installer learns after the key has been handled.
	if opts.out != "" {
		if err := checkDraftPath(opts.out, opts.force); err != nil {
			return err
		}
	}

	raw, err := readDocument(stdin, opts.in)
	if err != nil {
		return err
	}
	key, err := readSigningKey(opts)
	if err != nil {
		return err
	}

	doc, supplied, decodeErr := binding.DecodeDocument(raw)
	if decodeErr != nil {
		return refusedError{decodeErr}
	}
	if err := attachControlPaths(&doc, opts.controlPaths); err != nil {
		return err
	}
	if err := fillOwnedFields(state, &doc, supplied, key, opts); err != nil {
		return err
	}

	envelope, signature, signErr := doc.SignedEnvelope(key)
	if signErr != nil {
		return refusedError{signErr}
	}
	accepted, verifyErr := binding.VerifyOffline(envelope)
	if verifyErr != nil {
		// The producer's own check admitted what the verifier refuses. That is
		// a defect in this tool, not in the document, and nothing is written.
		return fmt.Errorf("the signed envelope failed verification: %v", verifyErr)
	}
	envelope = append(envelope, '\n')

	if opts.out != "" {
		if writeErr := writeDraft(opts.out, envelope, opts.force); writeErr != nil {
			return writeErr
		}
	}
	return reportSigned(state, accepted, signature, envelope, opts.out)
}

func readDocument(stdin io.Reader, in string) ([]byte, error) {
	var source io.Reader = stdin
	if in != "-" {
		file, err := os.Open(in)
		if err != nil {
			return nil, fmt.Errorf("failed to open the document: %w", err)
		}
		defer file.Close()
		source = file
	}
	raw, err := readBounded(source, documentReadLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to read the document: %w", err)
	}
	return raw, nil
}

// readSigningKey reads the key from the file or descriptor named, and from
// nowhere else. A file another user can read is refused: a commissioning key
// that has been readable by others is not one this tool should sign with.
func readSigningKey(opts signOptions) (ed25519.PrivateKey, error) {
	var source io.Reader
	if opts.keyFDGiven {
		if opts.keyFD < 0 {
			return nil, errors.New("--key-fd is not a descriptor")
		}
		file := os.NewFile(uintptr(opts.keyFD), "key")
		if file == nil {
			return nil, fmt.Errorf("descriptor %d is not open", opts.keyFD)
		}
		defer file.Close()
		source = file
	} else {
		// No error below repeats the --key value. A value that was the key
		// itself rather than a path would otherwise be echoed by the failure
		// to open it, which is the one place the rule against taking a key
		// from a flag could still leak one.
		if looksLikeKeyMaterial(opts.keyPath) {
			return nil, errors.New(
				"--key takes a file path; the value given looks like key material and was not used")
		}
		// Opened without following a link, then judged by what was opened:
		// a check on the path before the open would describe whatever the
		// path named at that moment, not the file this reads.
		file, err := os.OpenFile(opts.keyPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			if errors.Is(err, syscall.ELOOP) {
				return nil, errors.New("the key path is a symbolic link; name the file itself")
			}
			return nil, fmt.Errorf("failed to open the key: %w", withoutPath(err))
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return nil, fmt.Errorf("failed to inspect the key: %w", withoutPath(err))
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New("the key path is not a regular file")
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf(
				"the key file is readable by others (mode %04o); a commissioning key "+
					"is kept at 0600", info.Mode().Perm())
		}
		source = file
	}
	data, err := readBounded(source, keyReadLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to read the key: %w", err)
	}
	key, parseErr := binding.ParsePrivateKey(data)
	if parseErr != nil {
		return nil, parseErr
	}
	return key, nil
}

// looksLikeKeyMaterial recognises the two spellings ParsePrivateKey reads,
// given where a path belongs.
func looksLikeKeyMaterial(value string) bool {
	trimmed := strings.TrimSpace(value)
	if strings.Contains(trimmed, "PRIVATE KEY") {
		return true
	}
	if len(trimmed) != 2*ed25519.SeedSize {
		return false
	}
	_, err := hex.DecodeString(trimmed)
	return err == nil
}

// withoutPath keeps the errno and drops the path an *os.PathError carries.
func withoutPath(err error) error {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}
	return err
}

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("more than %d bytes, which nothing this command reads is", limit)
	}
	return data, nil
}

// attachControlPaths puts each exported leg on the zone it names. A zone that
// already carries a leg keeps it; signing does not replace a proof.
func attachControlPaths(doc *binding.Binding, specs []string) error {
	for _, spec := range specs {
		zoneID, path, ok := strings.Cut(spec, "=")
		if !ok || zoneID == "" || path == "" {
			return fmt.Errorf("--control-path %q is not zone=file", spec)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read the control leg for zone %q: %w", zoneID, err)
		}
		leg, decodeErr := binding.DecodeControlPath(raw)
		if decodeErr != nil {
			return refusedError{fmt.Errorf("control leg for zone %q: %w", zoneID, decodeErr)}
		}
		attached := false
		for i := range doc.Zones {
			if doc.Zones[i].ZoneID != zoneID {
				continue
			}
			if doc.Zones[i].Proof.ControlPath != nil {
				return refusedError{fmt.Errorf(
					"zone %q already carries a control leg; sign does not replace one", zoneID)}
			}
			doc.Zones[i].Proof.ControlPath = &leg
			attached = true
		}
		if !attached {
			return refusedError{fmt.Errorf("the document has no zone %q to attach a control leg to", zoneID)}
		}
	}
	return nil
}

// fillOwnedFields settles the fields signing owns: absent ones are filled from
// the flags, the key and the clock; present ones are kept, and a flag that
// disagrees with one is refused rather than applied.
func fillOwnedFields(
	state *rootState, doc *binding.Binding, supplied binding.Supplied,
	key ed25519.PrivateKey, opts signOptions,
) error {
	for _, field := range []struct {
		name     string
		flag     ownedFlag
		supplied bool
		target   *string
	}{
		{"signer_id", opts.signerID, supplied.SignerID, &doc.SignerID},
		{"actor", opts.actor, supplied.Actor, &doc.Actor},
		{"reason", opts.reason, supplied.Reason, &doc.Reason},
	} {
		switch {
		case field.flag.given && strings.TrimSpace(field.flag.value) == "":
			return refusedError{fmt.Errorf("--%s is empty", strings.ReplaceAll(field.name, "_", "-"))}
		case field.supplied && field.flag.given && *field.target != field.flag.value:
			return refusedError{fmt.Errorf(
				"the document records %s %q and --%s gives %q; signing does not rewrite a document",
				field.name, *field.target, strings.ReplaceAll(field.name, "_", "-"), field.flag.value)}
		case !field.supplied && !field.flag.given:
			return refusedError{fmt.Errorf(
				"the document carries no %s; pass --%s", field.name, strings.ReplaceAll(field.name, "_", "-"))}
		case !field.supplied:
			*field.target = field.flag.value
		}
	}
	named := binding.SigningKeyName(key.Public().(ed25519.PublicKey))
	if supplied.SigningKey && doc.SigningKey != named {
		return refusedError{fmt.Errorf(
			"the document names signing_key %q and this key is %q", doc.SigningKey, named)}
	}
	doc.SigningKey = named
	if !supplied.IssuedAtMs {
		doc.IssuedAtMs = state.nowMs()
	}
	return nil
}

func reportSigned(
	state *rootState, accepted *binding.Accepted, signature string, envelope []byte, out string,
) error {
	if state.json {
		result := map[string]any{
			"device_id":            accepted.DeviceID,
			"binding_seq":          accepted.BindingSeq,
			"canonical_sha256":     accepted.CanonicalHash,
			"signature":            signature,
			"verified_offline":     binding.OfflineStages,
			"decided_at_delivery":  binding.DeliveryStages,
			"deferred_to_delivery": binding.DeferredChecks,
		}
		if out != "" {
			result["path"] = out
		} else {
			result["envelope"] = json.RawMessage(envelope)
		}
		return output.JSON(state.stdout, map[string]any{"ok": true, "result": result})
	}
	report := state.stdout
	if out == "" {
		if _, err := state.stdout.Write(envelope); err != nil {
			return err
		}
		report = state.stderr
	} else {
		fmt.Fprintf(report, "wrote the signed envelope to %s\n", out)
	}
	fmt.Fprintf(report, "signed binding_seq %d for device %s\n", accepted.BindingSeq, accepted.DeviceID)
	fmt.Fprintf(report, "canonical %s\n", accepted.CanonicalHash)
	fmt.Fprintf(report, "signature %s\n", signature)
	fmt.Fprintf(report, "verified offline: %s\n", strings.Join(binding.OfflineStages, ", "))
	fmt.Fprintf(report, "decided at delivery: %s\n", strings.Join(binding.DeliveryStages, ", "))
	fmt.Fprintf(report, "deferred to delivery: %s\n", strings.Join(binding.DeferredChecks, "; "))
	return nil
}
