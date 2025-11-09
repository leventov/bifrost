package lib

import (
	"context"
	"strings"
	"sync"

	"github.com/maximhq/bifrost/core/schemas"
)

// vkAllowedCache caches computed allowed providers/models for a VK value.
// Key: virtual key value (string)
// Val: map[providerLower]map[model]struct{} ; nil model map => all models allowed for that provider
var vkAllowedCache sync.Map

// FilterModelsByVirtualKey filters the list models response according to the VK (x-bf-vk) present in ctx.
// - No-op if governance is disabled, VK missing, store unavailable, or VK has no provider configs.
// - If VK provider config has empty AllowedModels, all models for that provider are allowed.
// - Otherwise only explicitly allowed models are retained.
func FilterModelsByVirtualKey(ctx context.Context, store HandlerStore, resp *schemas.BifrostListModelsResponse) {
	if resp == nil || len(resp.Data) == 0 || store == nil || !store.IsGovernanceEnabled() {
		return
	}
	// Extract VK from context
	vkValue, _ := ctx.Value(schemas.BifrostContextKeyVirtualKey).(string)
	if vkValue == "" {
		return
	}
	cs := store.GetConfigStore()
	if cs == nil {
		return
	}
	// Fetch VK with provider configs
	vk, err := cs.GetVirtualKeyByValue(ctx, vkValue)
	if err != nil || vk == nil || !vk.IsActive {
		return
	}
	if len(vk.ProviderConfigs) == 0 {
		return // No restrictions configured
	}
	// Build or get cached allowed map
	allowedAny, ok := vkAllowedCache.Load(vkValue)
	var allowed map[string]map[string]struct{}
	if ok {
		allowed, _ = allowedAny.(map[string]map[string]struct{})
	}
	if allowed == nil {
		allowed = make(map[string]map[string]struct{}, len(vk.ProviderConfigs))
		for _, pc := range vk.ProviderConfigs {
			providerName := strings.ToLower(pc.Provider)
			if len(pc.AllowedModels) == 0 {
				// nil set denotes all models allowed for this provider
				allowed[providerName] = nil
				continue
			}
			modelSet := make(map[string]struct{}, len(pc.AllowedModels))
			for _, m := range pc.AllowedModels {
				modelSet[m] = struct{}{}
			}
			allowed[providerName] = modelSet
		}
		vkAllowedCache.Store(vkValue, allowed)
	}

	// Apply filtering
	filtered := make([]schemas.Model, 0, len(resp.Data))
	for _, model := range resp.Data {
		providerParsed, modelName := schemas.ParseModelString(model.ID, "")
		providerKey := strings.ToLower(string(providerParsed))
		allowedSet, ok := allowed[providerKey]
		if !ok {
			// Provider not allowed
			continue
		}
		// If nil => all models for this provider allowed
		if allowedSet == nil {
			filtered = append(filtered, model)
			continue
		}
		// Otherwise require explicit model allow
		if _, ok := allowedSet[modelName]; ok {
			filtered = append(filtered, model)
		}
	}
	resp.Data = filtered
}


