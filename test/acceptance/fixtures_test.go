package acceptance_test

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// Archive builders. Fixtures are built at test time and never committed. Each
// builder writes to dest and fails the test on any error.

// zipEntry is one zip member. The name is written as given, so tests can use
// hostile names such as "../../evil.sh".
type zipEntry struct {
	name string
	data []byte
	mode fs.FileMode // zero means a regular file
}

// dirEntries lists the files below src as zip entries named prefix plus their
// slash-separated path relative to src.
func dirEntries(t *testing.T, src, prefix string) []zipEntry {
	t.Helper()
	var entries []zipEntry
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		entries = append(entries, zipEntry{name: prefix + filepath.ToSlash(rel), data: b})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

// zipBytes returns the zip of entries.
func zipBytes(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	p := filepath.Join(t.TempDir(), "x.zip")
	zipEntries(t, p, entries)
	b, err := os.ReadFile(p) // #nosec G304 -- test fixture path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// writeBytes writes b to dest.
func writeBytes(t *testing.T, dest string, b []byte) {
	t.Helper()
	if err := os.WriteFile(dest, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// sfxStub is the start of a PE file: a DOS header whose PE offset points at the PE signature.
// It is not executable.
func sfxStub() []byte {
	stub := make([]byte, 0x80)
	copy(stub, "MZ")
	stub[0x3c] = 0x40
	copy(stub[0x40:], "PE\x00\x00")
	return stub
}

// nestedZips writes inner as a zip, then wraps it in a zip of its own levels-1 more times,
// so the zip holding inner sits at container depth levels-1 when dest is analyzed.
func nestedZips(t *testing.T, dest string, levels int, inner []zipEntry) {
	t.Helper()
	data := zipBytes(t, inner)
	for range levels - 1 {
		data = zipBytes(t, []zipEntry{{name: "next.zip", data: data}})
	}
	writeBytes(t, dest, data)
}

// zipDir zips the files below src into dest. Member names are slash-separated
// paths relative to src.
func zipDir(t *testing.T, src, dest string) {
	t.Helper()
	zipEntries(t, dest, dirEntries(t, src, ""))
}

// zipEntries writes a zip with the entries in order, using their raw names.
func zipEntries(t *testing.T, dest string, entries []zipEntry) {
	t.Helper()
	f, err := os.Create(dest) // #nosec G304 -- test fixture path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.mode != 0 {
			h.SetMode(e.mode)
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// zipZeros writes a zip with one entry of size zero bytes, streamed so the test
// never holds it in memory.
func zipZeros(t *testing.T, dest, name string, size int64) {
	t.Helper()
	f, err := os.Create(dest) // #nosec G304 -- test fixture path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(w, zeroReader{}, size); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// tarEntry is one tar member. A zero typeflag means a regular file.
type tarEntry struct {
	name     string
	data     []byte
	typeflag byte
	link     string
}

// tarGz writes a gzip-compressed tar with the entries in order.
func tarGz(t *testing.T, dest string, entries []tarEntry) {
	t.Helper()
	f, err := os.Create(dest) // #nosec G304 -- test fixture path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		typeflag := e.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Typeflag: typeflag, Linkname: e.link, Mode: 0o644}
		if typeflag == tar.TypeReg {
			h.Size = int64(len(e.data))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// benignDocx writes a minimal docx with one internal and one external hyperlink to dest.
func benignDocx(t *testing.T, dest string) {
	t.Helper()
	zipEntries(t, dest, benignDocxEntries())
}

// benignDocxEntries are the members of benignDocx.
func benignDocxEntries() []zipEntry {
	const relType = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
	return []zipEntry{
		{name: "[Content_Types].xml", data: []byte(`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>`)},
		{name: "word/document.xml", data: []byte(`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Guide</w:t></w:r></w:p></w:body></w:document>`)},
		{name: "word/_rels/document.xml.rels", data: []byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n" +
			`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` + "\n" +
			`  <Relationship Id="rId1" Type="` + relType + `hyperlink" Target="#chapter2"/>` + "\n" +
			`  <Relationship Id="rId2" Type="` + relType + `hyperlink" Target="https://docs.sinkhole.test/guide" TargetMode="External"/>` + "\n" +
			`</Relationships>` + "\n")},
	}
}
