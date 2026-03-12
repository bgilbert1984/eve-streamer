package main

import (
	"testing"
)

func TestCaptureEngineFactory(t *testing.T) {
	factory := NewCaptureEngineFactory()

	// Test case: requested engine exists but might fail validation if not run as root
	// We use "suricata" as a safe test if eve.json doesn't exist, it should trigger fallback
	cfg := EngineConfig{
		Mode:          "suricata",
		EveFile:       "/tmp/non-existent-eve.json",
		Iface:         "lo",
		AllowFallback: true,
	}

	engine, err := factory.Create(cfg)
	if err != nil {
		t.Fatalf("Factory failed to create engine: %v", err)
	}

	if engine == nil {
		t.Fatal("Factory returned nil engine")
	}

	t.Logf("Created engine: %s", engine.Name())

	// Test case: unknown mode
	cfgUnknown := EngineConfig{
		Mode: "non-existent-engine",
	}
	_, err = factory.Create(cfgUnknown)
	if err == nil {
		t.Error("Factory should have failed for unknown engine mode")
	}
}

func TestListEngines(t *testing.T) {
	factory := NewCaptureEngineFactory()
	engines := factory.ListEngines()

	if len(engines) == 0 {
		t.Error("Factory returned empty engine list")
	}

	for _, eng := range engines {
		t.Logf("Found registered engine: %s (RawPackets: %v)", eng.Name, eng.Capabilities.EmitsRawPackets)
	}
}
