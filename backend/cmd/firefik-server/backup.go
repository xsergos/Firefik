package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const backupMagic = "firefik-cp-backup"

const backupSchemaVersion = 1

type backupManifest struct {
	Magic         string    `json:"magic"`
	SchemaVersion int       `json:"schema_version"`
	CreatedAt     time.Time `json:"created_at"`
	DBPath        string    `json:"db_path"`
	CAPath        string    `json:"ca_path"`
	DBSHA256      string    `json:"db_sha256"`
}

func runBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	dbPath := fs.String("db", defaultDBPath(), "sqlite path to back up")
	caStateDir := fs.String("ca-state-dir", defaultCAStateDir(), "mini-CA state dir to back up (optional)")
	out := fs.String("out", "", "output tar.gz path (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("--out is required")
	}
	if _, err := os.Stat(*dbPath); err != nil {
		return fmt.Errorf("db file %s: %w", *dbPath, err)
	}

	tmp := *out + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	dbHash, err := writeFileToTar(tw, *dbPath, "db/firefik.db")
	if err != nil {
		closeAll(tw, gz, f)
		os.Remove(tmp)
		return err
	}
	if *caStateDir != "" {
		if err := writeDirToTar(tw, *caStateDir, "ca"); err != nil {
			closeAll(tw, gz, f)
			os.Remove(tmp)
			return err
		}
	}

	mf := backupManifest{
		Magic:         backupMagic,
		SchemaVersion: backupSchemaVersion,
		CreatedAt:     time.Now().UTC(),
		DBPath:        *dbPath,
		CAPath:        *caStateDir,
		DBSHA256:      dbHash,
	}
	mfBytes, err := json.MarshalIndent(mf, "", "  ")
	if err != nil {
		closeAll(tw, gz, f)
		os.Remove(tmp)
		return err
	}
	if err := writeBytesToTar(tw, "manifest.json", mfBytes); err != nil {
		closeAll(tw, gz, f)
		os.Remove(tmp)
		return err
	}

	if err := closeAll(tw, gz, f); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, *out); err != nil {
		os.Remove(tmp)
		return err
	}
	fmt.Fprintf(os.Stderr, "backup written: %s (db sha256=%s)\n", *out, dbHash)
	return nil
}

func runRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	src := fs.String("from", "", "backup tar.gz to restore (required)")
	dbPath := fs.String("db", defaultDBPath(), "destination sqlite path")
	caStateDir := fs.String("ca-state-dir", defaultCAStateDir(), "destination mini-CA state dir")
	dryRun := fs.Bool("dry-run", false, "validate manifest only, do not write")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *src == "" {
		return errors.New("--from is required")
	}

	mf, err := readManifest(*src)
	if err != nil {
		return err
	}
	if mf.Magic != backupMagic {
		return fmt.Errorf("not a firefik backup: magic=%q", mf.Magic)
	}
	if mf.SchemaVersion > backupSchemaVersion {
		return fmt.Errorf("backup schema %d is newer than supported (%d)", mf.SchemaVersion, backupSchemaVersion)
	}
	if *dryRun {
		fmt.Fprintf(os.Stderr, "manifest ok: created=%s schema=%d\n", mf.CreatedAt.Format(time.RFC3339), mf.SchemaVersion)
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(*dbPath), 0o700); err != nil {
		return err
	}
	if *caStateDir != "" {
		if err := os.MkdirAll(*caStateDir, 0o700); err != nil {
			return err
		}
	}
	return extractBackup(*src, *dbPath, *caStateDir)
}

func writeFileToTar(tw *tar.Writer, srcPath, name string) (string, error) {
	f, err := os.Open(srcPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	hdr := &tar.Header{
		Name:    name,
		Mode:    0o600,
		Size:    stat.Size(),
		ModTime: stat.ModTime(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return "", err
	}
	if _, err := io.Copy(io.MultiWriter(tw, hash), f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func writeDirToTar(tw *tar.Writer, srcDir, baseName string) error {
	return filepath.Walk(srcDir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(srcDir, p)
		_, herr := writeFileToTar(tw, p, filepath.ToSlash(filepath.Join(baseName, rel)))
		return herr
	})
}

func writeBytesToTar(tw *tar.Writer, name string, data []byte) error {
	if err := tw.WriteHeader(&tar.Header{
		Name:    name,
		Mode:    0o600,
		Size:    int64(len(data)),
		ModTime: time.Now(),
	}); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func readManifest(src string) (*backupManifest, error) {
	f, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, errors.New("manifest.json missing in backup")
		}
		if err != nil {
			return nil, err
		}
		if hdr.Name != "manifest.json" {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		var mf backupManifest
		if err := json.Unmarshal(body, &mf); err != nil {
			return nil, err
		}
		return &mf, nil
	}
}

func extractBackup(src, dbDest, caDest string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch {
		case hdr.Name == "db/firefik.db":
			if err := writeStream(tr, dbDest); err != nil {
				return err
			}
		case strings.HasPrefix(hdr.Name, "ca/") && caDest != "":
			rel := strings.TrimPrefix(hdr.Name, "ca/")
			dest := filepath.Join(caDest, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
				return err
			}
			if err := writeStream(tr, dest); err != nil {
				return err
			}
		}
	}
}

func writeStream(r io.Reader, dest string) error {
	tmp := dest + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

func closeAll(closers ...io.Closer) error {
	var first error
	for _, c := range closers {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
