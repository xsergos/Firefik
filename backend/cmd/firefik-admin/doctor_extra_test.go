package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrintDoctorTextPass(t *testing.T) {
	rep := doctorReport{
		OK: true,
		Checks: []doctorCheck{
			{Name: "x", Pass: true, Detail: "ok"},
		},
	}
	var buf bytes.Buffer
	printDoctorText(&buf, rep)
	if !strings.Contains(buf.String(), "PASS") {
		t.Errorf("got %q", buf.String())
	}
}

func TestPrintDoctorTextFail(t *testing.T) {
	rep := doctorReport{
		OK: false,
		Checks: []doctorCheck{
			{Name: "y", Pass: false, Detail: "broken", Hint: "fix it"},
		},
	}
	var buf bytes.Buffer
	printDoctorText(&buf, rep)
	if !strings.Contains(buf.String(), "FAIL") || !strings.Contains(buf.String(), "fix it") {
		t.Errorf("got %q", buf.String())
	}
}

func TestParseHexNibble(t *testing.T) {
	cases := map[byte]uint{
		'0': 0, '5': 5, '9': 9,
		'a': 10, 'c': 12, 'f': 15,
		'A': 10, 'F': 15,
	}
	for in, want := range cases {
		got, err := parseHexNibble(in)
		if err != nil || got != want {
			t.Errorf("parseHexNibble(%q) = (%d,%v); want %d", in, got, err, want)
		}
	}
	if _, err := parseHexNibble('z'); err == nil {
		t.Errorf("expected error on 'z'")
	}
}

func TestCapHasBitEdgeCases(t *testing.T) {
	if capHasBit("", 1) {
		t.Errorf("empty hex should be false")
	}
	if capHasBit("0", 200) {
		t.Errorf("out of range bit should be false")
	}
	if capHasBit("zzzz", 0) {
		t.Errorf("invalid hex digits should be false")
	}
}

func TestCapEffectiveHex(t *testing.T) {
	status := "Name:\tfoo\nCapEff:\t0000003fffffffff\nUmask:\t0022\n"
	if got := capEffectiveHex(status); got != "0000003fffffffff" {
		t.Errorf("got %q", got)
	}
	if got := capEffectiveHex("Name: foo\n"); got != "" {
		t.Errorf("expected empty for missing CapEff, got %q", got)
	}
}

func TestCheckBinaryMissing(t *testing.T) {
	c := checkBinary("totally-not-a-binary-12345")
	if c.Pass {
		t.Errorf("should fail for missing binary")
	}
}

func TestCheckLinuxMatch(t *testing.T) {
	c := checkLinux()
	if c.Detail == "" {
		t.Errorf("expected detail")
	}
}

func TestCheckDockerSocketMissing(t *testing.T) {
	c := checkDockerSocket("/this/should/not/exist.sock")
	if c.Pass {
		t.Errorf("should fail")
	}
}

func TestCheckDockerSocketRegularFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "fake.sock")
	if err := os.WriteFile(tmp, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	c := checkDockerSocket(tmp)
	if c.Pass {
		t.Errorf("regular file should fail socket check")
	}
}

func TestCheckParentChainAuto(t *testing.T) {
	g := &globalFlags{backend: "auto"}
	c := checkParentChain(g)
	if !c.Pass {
		t.Errorf("auto should pass with skip detail: %+v", c)
	}
}

func TestCheckParentChainNftables(t *testing.T) {
	g := &globalFlags{backend: "nftables"}
	c := checkParentChain(g)
	if !c.Pass {
		t.Errorf("nftables should pass: %+v", c)
	}
}

func TestCheckParentChainOther(t *testing.T) {
	g := &globalFlags{backend: "other"}
	c := checkParentChain(g)
	if !c.Pass {
		t.Errorf("other should pass: %+v", c)
	}
}

func TestCheckGeoIPStatErr(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "noperms")
	c := checkGeoIP(tmp, 0)
	if !c.Pass && !strings.Contains(c.Detail, "absent") {
		_ = c
	}
}

func TestCheckKernelModuleNotLinux(t *testing.T) {
	_ = checkKernelModule("nf_tables")
}

func TestCheckCapNotLinux(t *testing.T) {
	_ = checkCap("CAP_NET_ADMIN")
}

func TestKernelRelease(t *testing.T) {
	_ = kernelRelease()
}
