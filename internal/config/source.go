package config

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// reloadCheck is how often Source looks at the file for changes.
const reloadCheck = 2 * time.Second

// Source returns the current configuration, reloading the file when it
// changes, so edits apply without a restart. It is Named: the machine the
// bridge runs on appears under its own name rather than "local".
type Source struct {
	Path string
	// Fallback makes the configuration when the file does not exist. It is
	// called again on each check while the file is missing.
	Fallback func() *Config

	mu      sync.Mutex
	cfg     *Config
	modTime time.Time
	exists  bool
	checked time.Time
}

// Get returns the configuration. If the file has become invalid, it keeps
// the last good one and logs why.
func (s *Source) Get() *Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg != nil && time.Since(s.checked) < reloadCheck {
		return s.cfg
	}
	s.checked = time.Now()
	info, err := os.Stat(s.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		s.cfg, s.exists = s.Fallback().Named(), false
	case err != nil:
		log.Printf("config: %v", err)
	case !s.exists || !info.ModTime().Equal(s.modTime) || s.cfg == nil:
		cfg, err := Load(s.Path)
		if err != nil {
			log.Printf("config: keeping the previous configuration: %v", err)
			if s.cfg == nil {
				s.cfg = &Config{}
			}
			break
		}
		if s.exists {
			log.Printf("config: reloaded %s", s.Path)
		}
		s.cfg, s.modTime, s.exists = cfg.Named(), info.ModTime(), true
	}
	return s.cfg
}

// Exists reports whether the configuration came from the file.
func (s *Source) Exists() bool {
	s.Get()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exists
}

// LoadFile reads the file at path, or returns an empty configuration if it
// does not exist. Unlike Load, it never fills in defaults, so that what is
// saved back is only what the user set.
func LoadFile(path string) (*Config, error) {
	c, err := Load(path)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return &Config{Hosts: map[string]Host{}}, nil
	}
	if c.Hosts == nil {
		c.Hosts = map[string]Host{}
	}
	return c, nil
}

// Save writes c to path, replacing the file atomically.
func (c *Config) Save(path string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
