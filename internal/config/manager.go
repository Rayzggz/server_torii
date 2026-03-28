package config

import (
	"fmt"
	"log"
	"runtime"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
	"sync/atomic"
)

// SiteConfigSnapshot represents a complete, immutable snapshot of the active site configurations and their derived states.
type SiteConfigSnapshot struct {
	SiteRules map[string]*RuleSet
}

// ConfigManager handles the thread-safe swapping of site configuration snapshots.
type ConfigManager struct {
	snapshot atomic.Pointer[SiteConfigSnapshot]
}

// Manager is the global configuration manager instance.
var Manager *ConfigManager

// InitManager initializes the global ConfigManager and builds the initial snapshot.
func InitManager(cfg *MainConfig, sharedMem *dataType.SharedMemory) error {
	Manager = &ConfigManager{}
	err := Manager.Reload(cfg, sharedMem)
	if err != nil {
		return err
	}
	return nil
}

// Get returns the current, immutable site configuration snapshot.
// Calling this at the start of a request guarantees that the request sees a consistent state.
func (m *ConfigManager) Get() *SiteConfigSnapshot {
	return m.snapshot.Load()
}

// Set forcefully replaces the current configuration snapshot with a new one.
func (m *ConfigManager) Set(snap *SiteConfigSnapshot) {
	m.snapshot.Store(snap)
}

// Reload re-reads all SiteRules and substitutes the snapshot without interrupting current requests, provided that the new limits do not exceed the pre-allocated SharedMemory capacities.
func (m *ConfigManager) Reload(cfg *MainConfig, sharedMem *dataType.SharedMemory) error {
	log.Println("[INFO] Reloading site configurations...")

	siteRules, err := LoadSiteRules(cfg)
	if err != nil {
		return fmt.Errorf("failed to reload site rules: %w", err)
	}

	// Derive maximum cache life times needed for limits across all sites to validate against sharedMem limits.
	maxSpeedLimitTime := int64(0)
	maxSameURILimitTime := int64(0)
	maxFailureLimitTime := int64(0)
	maxCaptchaFailureLimitTime := int64(0)

	for _, rules := range siteRules {
		speedTime := utils.FindMaxRateTime(rules.HTTPFloodRule.HTTPFloodSpeedLimit)
		uriTime := utils.FindMaxRateTime(rules.HTTPFloodRule.HTTPFloodSameURILimit)
		failureTime := utils.FindMaxRateTime(rules.HTTPFloodRule.HTTPFloodFailureLimit)
		if speedTime > maxSpeedLimitTime {
			maxSpeedLimitTime = speedTime
		}
		if uriTime > maxSameURILimitTime {
			maxSameURILimitTime = uriTime
		}
		if failureTime > maxFailureLimitTime {
			maxFailureLimitTime = failureTime
		}
		captchaFailureTime := utils.FindMaxRateTime(rules.CAPTCHARule.CaptchaFailureLimit)
		if captchaFailureTime > maxCaptchaFailureLimitTime {
			maxCaptchaFailureLimitTime = captchaFailureTime
		}
	}

	// Update SharedMemory Counters conditionally based on required capacity
	if sharedMem != nil {
		bucketCount := maxInt(runtime.NumCPU()*8, 16)

		// If counter doesn't exist or required size changed, re-allocate it (this clears old records)
		if sharedMem.HTTPFloodSpeedLimitCounter.Load() == nil || sharedMem.HTTPFloodSpeedLimitCounter.Load().GetSegSize() != maxSpeedLimitTime {
			sharedMem.HTTPFloodSpeedLimitCounter.Store(dataType.NewCounter(bucketCount, maxSpeedLimitTime))
		}

		if sharedMem.HTTPFloodSameURILimitCounter.Load() == nil || sharedMem.HTTPFloodSameURILimitCounter.Load().GetSegSize() != maxSameURILimitTime {
			sharedMem.HTTPFloodSameURILimitCounter.Store(dataType.NewCounter(bucketCount, maxSameURILimitTime))
		}

		if sharedMem.HTTPFloodFailureLimitCounter.Load() == nil || sharedMem.HTTPFloodFailureLimitCounter.Load().GetSegSize() != maxFailureLimitTime {
			sharedMem.HTTPFloodFailureLimitCounter.Store(dataType.NewCounter(bucketCount, maxFailureLimitTime))
		}

		if sharedMem.CaptchaFailureLimitCounter.Load() == nil || sharedMem.CaptchaFailureLimitCounter.Load().GetSegSize() != maxCaptchaFailureLimitTime {
			sharedMem.CaptchaFailureLimitCounter.Store(dataType.NewCounter(bucketCount, maxCaptchaFailureLimitTime))
		}
	}

	newSnapshot := &SiteConfigSnapshot{
		SiteRules: siteRules,
	}

	m.snapshot.Store(newSnapshot)
	log.Println("[INFO] Successfully applied new site configuration snapshot.")
	return nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
