// SPDX-License-Identifier: GPL-2.0

package manage

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/consi/xdpfilter/internal/config"
	"github.com/consi/xdpfilter/internal/dataplane"
	"github.com/consi/xdpfilter/internal/tuning"
)

var ErrConfigChanged = errors.New("config changed on disk; reload it before applying")

type Controller struct {
	Path         string
	Base         *config.Config
	Staged       *config.Config
	activePinDir string
	activeMu     sync.RWMutex
	hash         [32]byte
}

type ApplyResult struct {
	Changes  config.ChangeSet
	Previous *config.Config
	Active   bool
}

func NewController(path string) (*Controller, error) {
	c := &Controller{Path: path}
	if err := c.Reload(); err != nil {
		return nil, err
	}
	return c, nil
}

func fileHash(path string) ([32]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

func (c *Controller) Reload() error {
	cfg, err := config.Load(c.Path)
	if err != nil {
		return err
	}
	h, err := fileHash(c.Path)
	if err != nil {
		return err
	}
	c.Base, c.hash = cfg.Clone(), h
	if c.Staged == nil {
		c.Staged = cfg.Clone()
	} else {
		*c.Staged = *cfg.Clone()
	}
	if c.ActivePin() == "" {
		c.setActivePin(cfg.PinDir)
	}
	return nil
}

func (c *Controller) Dirty() bool { return !config.Diff(c.Base, c.Staged).Empty() }

// Apply validates, checks for concurrent file edits, updates the live map, and
// persists atomically. If persistence fails after a live update, it restores
// the prior map state on a best-effort basis.
func (c *Controller) Apply() (ApplyResult, error) {
	changes := config.Diff(c.Base, c.Staged)
	result := ApplyResult{Changes: changes, Previous: c.Base.Clone()}
	if changes.Empty() {
		return result, nil
	}
	h, err := fileHash(c.Path)
	if err != nil {
		return result, err
	}
	if h != c.hash {
		return result, ErrConfigChanged
	}
	next := c.Staged.Clone()
	if err := next.Validate(); err != nil {
		return result, err
	}

	maps, mapErr := dataplane.OpenPinned(c.ActivePin())
	if mapErr == nil {
		result.Active = true
		defer maps.Close()
		if err := dataplane.ReloadPolicy(maps, next); err != nil {
			return result, err
		}
	}
	if err := next.Save(c.Path); err != nil {
		if maps != nil {
			_ = dataplane.ReloadPolicy(maps, c.Base)
		}
		return result, err
	}
	newHash, err := fileHash(c.Path)
	if err != nil {
		return result, err
	}
	c.Base, c.hash = next.Clone(), newHash
	*c.Staged = *next.Clone() // retain the pointer captured by form callbacks
	if changes.Impact < config.ImpactReattach {
		c.setActivePin(next.PinDir)
	}
	return result, nil
}

func command(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

func ServiceAction(action string) (string, error) {
	allowed := map[string]bool{"start": true, "stop": true, "restart": true, "reload": true, "enable": true, "disable": true}
	if !allowed[action] {
		return "", fmt.Errorf("unsupported service action %q", action)
	}
	return command("systemctl", action, "xdpfilter")
}

func ServiceState() string {
	out, err := command("systemctl", "show", "xdpfilter", "--property=ActiveState,SubState,UnitFileState", "--value")
	if err != nil {
		return "unavailable"
	}
	parts := strings.Fields(out)
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, "/")
}

func (c *Controller) Reattach(previous *config.Config) error {
	if _, err := ServiceAction("stop"); err != nil {
		return fmt.Errorf("stop before reattach: %w", err)
	}
	if err := dataplane.Detach(previous.PinDir); err != nil {
		primary := err
		if saveErr := previous.Save(c.Path); saveErr != nil {
			return fmt.Errorf("detach old datapath: %v; restore config: %w", primary, saveErr)
		}
		_, restoreErr := ServiceAction("start")
		_ = c.Reload()
		if restoreErr != nil {
			return fmt.Errorf("detach old datapath: %v; restore old datapath: %w", primary, restoreErr)
		}
		return fmt.Errorf("reattach aborted and old configuration was restored: %w", primary)
	}
	if _, err := ServiceAction("start"); err == nil {
		c.setActivePin(c.Base.PinDir)
		return nil
	} else {
		primary := err
		if saveErr := previous.Save(c.Path); saveErr != nil {
			return fmt.Errorf("start new datapath: %v; restore config: %w", primary, saveErr)
		}
		_, restoreErr := ServiceAction("start")
		_ = c.Reload()
		if restoreErr != nil {
			return fmt.Errorf("start new datapath: %v; restore old datapath: %w", primary, restoreErr)
		}
		return fmt.Errorf("new datapath failed and old configuration was restored: %w", primary)
	}
}

func (c *Controller) ActivePin() string {
	c.activeMu.RLock()
	defer c.activeMu.RUnlock()
	return c.activePinDir
}

func (c *Controller) setActivePin(path string) {
	c.activeMu.Lock()
	c.activePinDir = path
	c.activeMu.Unlock()
}

func TuningPreview(cfg *config.Config) string {
	var out bytes.Buffer
	_ = tuning.New(cfg, true, &out).Apply()
	return out.String()
}

func TuningApply(cfg *config.Config) (string, error) {
	var out bytes.Buffer
	err := tuning.New(cfg, false, &out).Apply()
	return out.String(), err
}

func TuningRestore() (string, error) {
	var out bytes.Buffer
	err := tuning.Restore(&out)
	return out.String(), err
}
