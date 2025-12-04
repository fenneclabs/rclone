//go:build !plan9

package sftp

import (
	"fmt"
	"testing"

	"github.com/rclone/rclone/lib/encoder"
	"github.com/stretchr/testify/assert"
)

func TestShellEscapeUnix(t *testing.T) {
	for i, test := range []struct {
		unescaped, escaped string
	}{
		{"", ""},
		{"/this/is/harmless", "/this/is/harmless"},
		{"$(rm -rf /)", "\\$\\(rm\\ -rf\\ /\\)"},
		{"/test/\n", "/test/'\n'"},
		{":\"'", ":\\\"\\'"},
	} {
		got, err := quoteOrEscapeShellPath("unix", test.unescaped)
		assert.NoError(t, err)
		assert.Equal(t, test.escaped, got, fmt.Sprintf("Test %d unescaped = %q", i, test.unescaped))
	}
}

func TestShellEscapeCmd(t *testing.T) {
	for i, test := range []struct {
		unescaped, escaped string
		ok                 bool
	}{
		{"", "\"\"", true},
		{"c:/this/is/harmless", "\"c:/this/is/harmless\"", true},
		{"c:/test&notepad", "\"c:/test&notepad\"", true},
		{"c:/test\"&\"notepad", "", false},
	} {
		got, err := quoteOrEscapeShellPath("cmd", test.unescaped)
		if test.ok {
			assert.NoError(t, err)
			assert.Equal(t, test.escaped, got, fmt.Sprintf("Test %d unescaped = %q", i, test.unescaped))
		} else {
			assert.Error(t, err)
		}
	}
}

func TestShellEscapePowerShell(t *testing.T) {
	for i, test := range []struct {
		unescaped, escaped string
	}{
		{"", "''"},
		{"c:/this/is/harmless", "'c:/this/is/harmless'"},
		{"c:/test&notepad", "'c:/test&notepad'"},
		{"c:/test\"&\"notepad", "'c:/test\"&\"notepad'"},
		{"c:/test'&'notepad", "'c:/test''&''notepad'"},
	} {
		got, err := quoteOrEscapeShellPath("powershell", test.unescaped)
		assert.NoError(t, err)
		assert.Equal(t, test.escaped, got, fmt.Sprintf("Test %d unescaped = %q", i, test.unescaped))
	}
}

func TestParseHash(t *testing.T) {
	for i, test := range []struct {
		sshOutput, checksum string
	}{
		{"8dbc7733dbd10d2efc5c0a0d8dad90f958581821  RELEASE.md\n", "8dbc7733dbd10d2efc5c0a0d8dad90f958581821"},
		{"03cfd743661f07975fa2f1220c5194cbaff48451  -\n", "03cfd743661f07975fa2f1220c5194cbaff48451"},
	} {
		got := parseHash([]byte(test.sshOutput))
		assert.Equal(t, test.checksum, got, fmt.Sprintf("Test %d sshOutput = %q", i, test.sshOutput))
	}
}

func TestParseUsage(t *testing.T) {
	for i, test := range []struct {
		sshOutput string
		usage     [3]int64
	}{
		{"Filesystem     1K-blocks     Used Available Use% Mounted on\n/dev/root       91283092 81111888  10154820  89% /", [3]int64{93473886208, 83058573312, 10398535680}},
		{"Filesystem     1K-blocks  Used Available Use% Mounted on\ntmpfs             818256  1636    816620   1% /run", [3]int64{837894144, 1675264, 836218880}},
		{"Filesystem   1024-blocks     Used Available Capacity iused      ifree %iused  Mounted on\n/dev/disk0s2   244277768 94454848 149566920    39%  997820 4293969459    0%   /", [3]int64{250140434432, 96721764352, 153156526080}},
	} {
		gotSpaceTotal, gotSpaceUsed, gotSpaceAvail := parseUsage([]byte(test.sshOutput))
		assert.Equal(t, test.usage, [3]int64{gotSpaceTotal, gotSpaceUsed, gotSpaceAvail}, fmt.Sprintf("Test %d sshOutput = %q", i, test.sshOutput))
	}
}

// newTestFs creates a minimal Fs for testing path encoding
func newTestFs(absRoot string, enc encoder.MultiEncoder, shellType string) *Fs {
	return &Fs{
		absRoot:   absRoot,
		shellType: shellType,
		opt: Options{
			Enc: enc,
		},
	}
}

func TestRemotePathEncoding(t *testing.T) {
	// Test remotePath with various encodings
	for _, test := range []struct {
		name     string
		absRoot  string
		encoding string
		remote   string
		want     string
	}{
		{
			name:     "no encoding - simple path",
			absRoot:  "/home/user",
			encoding: "None",
			remote:   "file.txt",
			want:     "/home/user/file.txt",
		},
		{
			name:     "no encoding - path with colon",
			absRoot:  "/home/user",
			encoding: "None",
			remote:   "test:file.txt",
			want:     "/home/user/test:file.txt",
		},
		{
			name:     "Win encoding - path with colon",
			absRoot:  "/home/user",
			encoding: "Win",
			remote:   "test:file.txt",
			want:     "/home/user/test：file.txt",
		},
		{
			name:     "Win encoding - path with multiple special chars",
			absRoot:  "/home/user",
			encoding: "Win",
			remote:   "file:name?.txt",
			want:     "/home/user/file：name？.txt",
		},
		{
			name:     "Win encoding - subdirectory with special chars",
			absRoot:  "/home/user",
			encoding: "Win",
			remote:   "dir:name/file?.txt",
			want:     "/home/user/dir：name/file？.txt",
		},
		{
			name:     "Win encoding - trailing space",
			absRoot:  "/home/user",
			encoding: "Win",
			remote:   "trailing space ",
			want:     "/home/user/trailing space␠",
		},
		{
			name:     "Win encoding - trailing period",
			absRoot:  "/home/user",
			encoding: "Win",
			remote:   "trailing.",
			want:     "/home/user/trailing．",
		},
		{
			name:     "Win encoding - nested dirs with special chars",
			absRoot:  "/data",
			encoding: "Win",
			remote:   "backup:/2024-01-01/file<1>.txt",
			want:     "/data/backup：/2024-01-01/file＜1＞.txt",
		},
		{
			name:     "Win encoding - empty remote",
			absRoot:  "/home/user",
			encoding: "Win",
			remote:   "",
			want:     "/home/user",
		},
		{
			name:     "Win encoding - root path",
			absRoot:  "/",
			encoding: "Win",
			remote:   "test:file.txt",
			want:     "/test：file.txt",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var enc encoder.MultiEncoder
			if test.encoding != "" && test.encoding != "None" {
				err := enc.Set(test.encoding)
				assert.NoError(t, err)
			}
			f := newTestFs(test.absRoot, enc, "unix")
			got := f.remotePath(test.remote)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestRemoteShellPathEncoding(t *testing.T) {
	// Test remoteShellPath with various encodings
	for _, test := range []struct {
		name         string
		absRoot      string
		encoding     string
		shellType    string
		pathOverride string
		remote       string
		want         string
	}{
		{
			name:      "unix shell - no encoding",
			absRoot:   "/home/user",
			encoding:  "None",
			shellType: "unix",
			remote:    "test:file.txt",
			want:      "/home/user/test:file.txt",
		},
		{
			name:      "unix shell - Win encoding",
			absRoot:   "/home/user",
			encoding:  "Win",
			shellType: "unix",
			remote:    "test:file.txt",
			want:      "/home/user/test：file.txt",
		},
		{
			name:      "unix shell - Win encoding nested path",
			absRoot:   "/home/user",
			encoding:  "Win",
			shellType: "unix",
			remote:    "dir:1/subdir?/file*.txt",
			want:      "/home/user/dir：1/subdir？/file＊.txt",
		},
		{
			name:         "unix shell - with path override",
			absRoot:      "/home/user",
			encoding:     "Win",
			shellType:    "unix",
			pathOverride: "/mnt/data",
			remote:       "test:file.txt",
			want:         "/mnt/data/test：file.txt",
		},
		{
			name:         "unix shell - with @ path override",
			absRoot:      "/home/user",
			encoding:     "Win",
			shellType:    "unix",
			pathOverride: "@/volume1",
			remote:       "test:file.txt",
			want:         "/volume1/home/user/test：file.txt",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var enc encoder.MultiEncoder
			if test.encoding != "" && test.encoding != "None" {
				err := enc.Set(test.encoding)
				assert.NoError(t, err)
			}
			f := &Fs{
				absRoot:   test.absRoot,
				shellType: test.shellType,
				opt: Options{
					Enc:          enc,
					PathOverride: test.pathOverride,
				},
			}
			got := f.remoteShellPath(test.remote)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestEncodingRoundTrip(t *testing.T) {
	// Test that encoding and decoding paths produces consistent results
	for _, test := range []struct {
		name     string
		encoding string
		paths    []string
	}{
		{
			name:     "Win encoding round trip",
			encoding: "Win",
			paths: []string{
				"simple.txt",
				"with:colon.txt",
				"with?question.txt",
				"with*asterisk.txt",
				"with<angle>brackets.txt",
				"with|pipe.txt",
				`with"quote.txt`,
				"trailing space ",
				"trailing.",
				"complex:path?with*many<special>chars|here.txt",
				"nested/dir:name/file?.txt",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var enc encoder.MultiEncoder
			err := enc.Set(test.encoding)
			assert.NoError(t, err)

			for _, path := range test.paths {
				// Encode path
				encoded := enc.FromStandardPath(path)
				// Decode back
				decoded := enc.ToStandardPath(encoded)
				// Should match original
				assert.Equal(t, path, decoded, "Round trip failed for path %q, encoded as %q", path, encoded)
			}
		})
	}
}

func TestEncodingInListOperation(t *testing.T) {
	// Test that the encoding used in List() produces correct results
	// This tests the pattern used in the actual List function
	for _, test := range []struct {
		name           string
		encoding       string
		dir            string
		fileName       string // name as returned by SFTP server (encoded)
		wantRemotePath string // what remotePath(dir) should produce
		wantRemote     string // final remote name after decoding
	}{
		{
			name:           "List with Win encoding",
			encoding:       "Win",
			dir:            "mydir",
			fileName:       "test：file.txt", // fullwidth colon as stored on server
			wantRemotePath: "/home/user/mydir",
			wantRemote:     "mydir/test:file.txt", // decoded back to standard
		},
		{
			name:           "List nested dir with Win encoding",
			encoding:       "Win",
			dir:            "parent:dir",
			fileName:       "file？.txt",
			wantRemotePath: "/home/user/parent：dir",
			wantRemote:     "parent:dir/file?.txt",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var enc encoder.MultiEncoder
			err := enc.Set(test.encoding)
			assert.NoError(t, err)

			f := newTestFs("/home/user", enc, "unix")

			// Test the encoding of the directory path (used for ReadDir)
			gotPath := f.remotePath(test.dir)
			assert.Equal(t, test.wantRemotePath, gotPath)

			// Test decoding of filename (simulating what List does)
			decodedName := enc.ToStandardName(test.fileName)
			gotRemote := test.dir + "/" + decodedName
			assert.Equal(t, test.wantRemote, gotRemote)
		})
	}
}
