// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package gitinterface

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInvokeGarbageCollector(t *testing.T) {
	tempDir := t.TempDir()
	repo := CreateTestGitRepository(t, tempDir, true)

	blobID, err := repo.WriteBlob([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}

	require.True(t, repo.HasObject(blobID))

	// Regular garbage collection should not remove the object
	err = repo.InvokeGarbageCollector(false)
	assert.Nil(t, err)
	assert.True(t, repo.HasObject(blobID))

	// However, garbage collection with aggressive options set should remove the
	// object
	err = repo.InvokeGarbageCollector(true)
	assert.Nil(t, err)
	assert.False(t, repo.HasObject(blobID))
}
