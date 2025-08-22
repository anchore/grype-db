package v6

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	grypeDB "github.com/anchore/grype/grype/db/v6"
)

func TestKnownOperatingSystemSpecifierOverrides(t *testing.T) {
	overrides := KnownOperatingSystemSpecifierOverrides()
	require.NotEmpty(t, overrides, "should have at least some OS overrides")

	// Test that we have some expected aliases
	aliasMap := make(map[string]grypeDB.OperatingSystemSpecifierOverride)
	for _, override := range overrides {
		aliasMap[override.Alias] = override
	}

	// Test RHEL aliases
	centos, exists := aliasMap["centos"]
	require.True(t, exists, "should have centos alias")
	require.NotNil(t, centos.ReplacementName)
	assert.Equal(t, "rhel", *centos.ReplacementName)

	alma, exists := aliasMap["alma"]
	require.True(t, exists, "should have alma alias")
	require.NotNil(t, alma.ReplacementName)
	assert.Equal(t, "rhel", *alma.ReplacementName)

	almalinux, exists := aliasMap["almalinux"]
	require.True(t, exists, "should have almalinux alias")
	require.NotNil(t, almalinux.ReplacementName)
	assert.Equal(t, "rhel", *almalinux.ReplacementName)

	// Test rolling releases
	arch, exists := aliasMap["arch"]
	require.True(t, exists, "should have arch alias")
	assert.True(t, arch.Rolling, "arch should be marked as rolling")

	wolfi, exists := aliasMap["wolfi"]
	require.True(t, exists, "should have wolfi alias")
	assert.True(t, wolfi.Rolling, "wolfi should be marked as rolling")

	// Test that version and version_pattern are mutually exclusive
	for _, override := range overrides {
		assert.False(t, override.Version != "" && override.VersionPattern != "",
			"override %s should not have both version and version_pattern set", override.Alias)
	}
}

func TestKnownPackageSpecifierOverrides(t *testing.T) {
	overrides := KnownPackageSpecifierOverrides()
	require.NotEmpty(t, overrides, "should have at least some package overrides")

	// Test that we have some expected ecosystems
	ecosystemMap := make(map[string]grypeDB.PackageSpecifierOverride)
	for _, override := range overrides {
		ecosystemMap[override.Ecosystem] = override
	}

	// Test some expected language ecosystems
	python, exists := ecosystemMap["python"]
	require.True(t, exists, "should have python ecosystem")
	require.NotNil(t, python.ReplacementEcosystem)

	java, exists := ecosystemMap["java"]
	require.True(t, exists, "should have java ecosystem")
	require.NotNil(t, java.ReplacementEcosystem)

	// Test legacy cases
	dpkg, exists := ecosystemMap["dpkg"]
	require.True(t, exists, "should have dpkg legacy ecosystem")
	require.NotNil(t, dpkg.ReplacementEcosystem)

	apkg, exists := ecosystemMap["apkg"]
	require.True(t, exists, "should have apkg legacy ecosystem")
	require.NotNil(t, apkg.ReplacementEcosystem)
}

func TestPtr(t *testing.T) {
	// Test that ptr function works correctly
	s := "test"
	p := ptr(s)
	require.NotNil(t, p)
	assert.Equal(t, s, *p)

	i := 42
	pi := ptr(i)
	require.NotNil(t, pi)
	assert.Equal(t, i, *pi)
}
