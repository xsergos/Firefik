package config

import (
	"context"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

const debounceInterval = 200 * time.Millisecond

func WatchFile(ctx context.Context, configPath string, logger *slog.Logger, onChange func()) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer w.Close()

	dir := filepath.Dir(configPath)
	base := filepath.Base(configPath)

	if err := w.Add(dir); err != nil {
		return err
	}

	logger.Info("watching config file", "path", configPath, "debounce_ms", debounceInterval.Milliseconds())

	var timer *time.Timer
	fire := make(chan struct{}, 1)

	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return nil

		case event, ok := <-w.Events:
			if !ok {
				return nil
			}
			if filepath.Base(event.Name) != base {
				continue
			}
			if !(event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename) || event.Has(fsnotify.Remove)) {
				continue
			}
			if timer == nil {
				timer = time.AfterFunc(debounceInterval, func() {
					select {
					case fire <- struct{}{}:
					default:
					}
				})
			} else {
				timer.Reset(debounceInterval)
			}

		case <-fire:
			logger.Info("config file changed, reloading (debounced)")
			onChange()
			timer = nil

		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			logger.Warn("config watcher error", "error", err)
		}
	}
}
