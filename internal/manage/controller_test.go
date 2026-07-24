package manage

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/consi/xdpfilter/internal/config"
)

func testController(t *testing.T) *Controller {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	c := config.Default()
	c.TrustedIface = "eth0"
	c.UntrustedIface = "eth1"
	c.PinDir = filepath.Join(t.TempDir(), "pins")
	if err := c.Save(p); err != nil {
		t.Fatal(err)
	}
	ctl, err := NewController(p)
	if err != nil {
		t.Fatal(err)
	}
	return ctl
}

func TestApplyOffline(t *testing.T) {
	c := testController(t)
	c.Staged.Mode = "enforce"
	r, err := c.Apply()
	if err != nil {
		t.Fatal(err)
	}
	if r.Active || r.Changes.Impact != config.ImpactLive {
		t.Fatalf("bad result: %+v", r)
	}
	got, err := config.Load(c.Path)
	if err != nil || got.Mode != "enforce" {
		t.Fatalf("persisted config: %v %+v", err, got)
	}
}

func TestApplyDetectsExternalEdit(t *testing.T) {
	c := testController(t)
	c.Staged.Mode = "enforce"
	if err := os.WriteFile(c.Path, []byte("changed"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := c.Apply()
	if !errors.Is(err, ErrConfigChanged) {
		t.Fatalf("got %v", err)
	}
}
