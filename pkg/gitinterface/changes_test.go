// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package gitinterface

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetFilePathsChangedByCommitRepository(t *testing.T) {
	tmpDir := t.TempDir()
	repo := CreateTestGitRepository(t, tmpDir, false)

	treeBuilder := NewTreeBuilder(repo)

	blobIDs := []Hash{}
	for i := 0; i < 3; i++ {
		blobID, err := repo.WriteBlob([]byte(fmt.Sprintf("%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		blobIDs = append(blobIDs, blobID)
	}

	emptyTree, err := treeBuilder.WriteTreeFromEntries(nil)
	if err != nil {
		t.Fatal(err)
	}

	// In each of the tests below, repo.Commit uses the test name as a ref
	// This allows us to use a single repo in all the tests without interference
	// For example, if we use a single repo and a single ref (say main), the test that
	// expects a commit with no parents will have a parent because of a commit created
	// in a previous test

	t.Run("modify single file", func(t *testing.T) {
		treeA, err := treeBuilder.WriteTreeFromEntries([]TreeEntry{NewEntryBlob("a", blobIDs[0])})
		if err != nil {
			t.Fatal(err)
		}

		treeB, err := treeBuilder.WriteTreeFromEntries([]TreeEntry{NewEntryBlob("a", blobIDs[1])})
		if err != nil {
			t.Fatal(err)
		}

		_, err = repo.Commit(treeA, testNameToRefName(t.Name()), "Test commit\n", false)
		if err != nil {
			t.Fatal(err)
		}

		cB, err := repo.Commit(treeB, testNameToRefName(t.Name()), "Test commit\n", false)
		if err != nil {
			t.Fatal(err)
		}

		diffs, err := repo.GetFilePathsChangedByCommit(cB)
		assert.Nil(t, err)
		assert.Equal(t, []string{"a"}, diffs)
	})

	t.Run("rename single file", func(t *testing.T) {
		treeA, err := treeBuilder.WriteTreeFromEntries([]TreeEntry{NewEntryBlob("a", blobIDs[0])})
		if err != nil {
			t.Fatal(err)
		}

		treeB, err := treeBuilder.WriteTreeFromEntries([]TreeEntry{NewEntryBlob("b", blobIDs[0])})
		if err != nil {
			t.Fatal(err)
		}

		_, err = repo.Commit(treeA, testNameToRefName(t.Name()), "Test commit\n", false)
		if err != nil {
			t.Fatal(err)
		}

		cB, err := repo.Commit(treeB, testNameToRefName(t.Name()), "Test commit\n", false)
		if err != nil {
			t.Fatal(err)
		}

		diffs, err := repo.GetFilePathsChangedByCommit(cB)
		assert.Nil(t, err)
		assert.Equal(t, []string{"a", "b"}, diffs)
	})

	t.Run("swap two files around", func(t *testing.T) {
		treeA, err := treeBuilder.WriteTreeFromEntries([]TreeEntry{NewEntryBlob("a", blobIDs[0]), NewEntryBlob("b", blobIDs[1])})
		if err != nil {
			t.Fatal(err)
		}

		treeB, err := treeBuilder.WriteTreeFromEntries([]TreeEntry{NewEntryBlob("a", blobIDs[1]), NewEntryBlob("b", blobIDs[0])})
		if err != nil {
			t.Fatal(err)
		}

		_, err = repo.Commit(treeA, testNameToRefName(t.Name()), "Test commit\n", false)
		if err != nil {
			t.Fatal(err)
		}

		cB, err := repo.Commit(treeB, testNameToRefName(t.Name()), "Test commit\n", false)
		if err != nil {
			t.Fatal(err)
		}

		diffs, err := repo.GetFilePathsChangedByCommit(cB)
		assert.Nil(t, err)
		assert.Equal(t, []string{"a", "b"}, diffs)
	})

	t.Run("create new file", func(t *testing.T) {
		treeA, err := treeBuilder.WriteTreeFromEntries([]TreeEntry{NewEntryBlob("a", blobIDs[0])})
		if err != nil {
			t.Fatal(err)
		}

		treeB, err := treeBuilder.WriteTreeFromEntries([]TreeEntry{NewEntryBlob("a", blobIDs[0]), NewEntryBlob("b", blobIDs[1])})
		if err != nil {
			t.Fatal(err)
		}

		_, err = repo.Commit(treeA, testNameToRefName(t.Name()), "Test commit\n", false)
		if err != nil {
			t.Fatal(err)
		}

		cB, err := repo.Commit(treeB, testNameToRefName(t.Name()), "Test commit\n", false)
		if err != nil {
			t.Fatal(err)
		}

		diffs, err := repo.GetFilePathsChangedByCommit(cB)
		assert.Nil(t, err)
		assert.Equal(t, []string{"b"}, diffs)
	})

	t.Run("delete file", func(t *testing.T) {
		treeA, err := treeBuilder.WriteTreeFromEntries([]TreeEntry{NewEntryBlob("a", blobIDs[0]), NewEntryBlob("b", blobIDs[1])})
		if err != nil {
			t.Fatal(err)
		}

		treeB, err := treeBuilder.WriteTreeFromEntries([]TreeEntry{NewEntryBlob("a", blobIDs[0])})
		if err != nil {
			t.Fatal(err)
		}

		_, err = repo.Commit(treeA, testNameToRefName(t.Name()), "Test commit\n", false)
		if err != nil {
			t.Fatal(err)
		}

		cB, err := repo.Commit(treeB, testNameToRefName(t.Name()), "Test commit\n", false)
		if err != nil {
			t.Fatal(err)
		}

		diffs, err := repo.GetFilePathsChangedByCommit(cB)
		assert.Nil(t, err)
		assert.Equal(t, []string{"b"}, diffs)
	})

	t.Run("modify file and create new file", func(t *testing.T) {
		treeA, err := treeBuilder.WriteTreeFromEntries([]TreeEntry{NewEntryBlob("a", blobIDs[0])})
		if err != nil {
			t.Fatal(err)
		}

		treeB, err := treeBuilder.WriteTreeFromEntries([]TreeEntry{NewEntryBlob("a", blobIDs[2]), NewEntryBlob("b", blobIDs[1])})
		if err != nil {
			t.Fatal(err)
		}

		_, err = repo.Commit(treeA, testNameToRefName(t.Name()), "Test commit\n", false)
		if err != nil {
			t.Fatal(err)
		}

		cB, err := repo.Commit(treeB, testNameToRefName(t.Name()), "Test commit\n", false)
		if err != nil {
			t.Fatal(err)
		}

		diffs, err := repo.GetFilePathsChangedByCommit(cB)
		assert.Nil(t, err)
		assert.Equal(t, []string{"a", "b"}, diffs)
	})

	t.Run("no parent", func(t *testing.T) {
		treeA, err := treeBuilder.WriteTreeFromEntries([]TreeEntry{NewEntryBlob("a", blobIDs[0])})
		if err != nil {
			t.Fatal(err)
		}

		cA, err := repo.Commit(treeA, testNameToRefName(t.Name()), "Test commit\n", false)
		if err != nil {
			t.Fatal(err)
		}

		diffs, err := repo.GetFilePathsChangedByCommit(cA)
		assert.Nil(t, err)
		assert.Equal(t, []string{"a"}, diffs)
	})

	t.Run("merge commit with commit matching parent", func(t *testing.T) {
		treeA, err := treeBuilder.WriteTreeFromEntries([]TreeEntry{NewEntryBlob("a", blobIDs[0])})
		if err != nil {
			t.Fatal(err)
		}

		treeB, err := treeBuilder.WriteTreeFromEntries([]TreeEntry{NewEntryBlob("a", blobIDs[1])})
		if err != nil {
			t.Fatal(err)
		}

		mainBranch := testNameToRefName(t.Name())
		featureBranch := testNameToRefName(t.Name() + " feature branch")

		// Write common commit for both branches
		cCommon, err := repo.Commit(emptyTree, mainBranch, "Initial commit\n", false)
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.SetReference(featureBranch, cCommon); err != nil {
			t.Fatal(err)
		}

		cA, err := repo.Commit(treeA, mainBranch, "Test commit\n", false)
		if err != nil {
			t.Fatal(err)
		}

		cB, err := repo.Commit(treeB, featureBranch, "Test commit\n", false)
		if err != nil {
			t.Fatal(err)
		}

		// Create a merge commit with two parents
		cM := repo.commitWithParents(t, treeB, []Hash{cA, cB}, "Merge commit\n", false)

		diffs, err := repo.GetFilePathsChangedByCommit(cM)
		assert.Nil(t, err)
		assert.Nil(t, diffs)
	})

	t.Run("merge commit with no matching parent", func(t *testing.T) {
		treeA, err := treeBuilder.WriteTreeFromEntries([]TreeEntry{NewEntryBlob("a", blobIDs[0])})
		if err != nil {
			t.Fatal(err)
		}

		treeB, err := treeBuilder.WriteTreeFromEntries([]TreeEntry{NewEntryBlob("b", blobIDs[1])})
		if err != nil {
			t.Fatal(err)
		}

		treeC, err := treeBuilder.WriteTreeFromEntries([]TreeEntry{NewEntryBlob("c", blobIDs[2])})
		if err != nil {
			t.Fatal(err)
		}

		mainBranch := testNameToRefName(t.Name())
		featureBranch := testNameToRefName(t.Name() + " feature branch")

		// Write common commit for both branches
		cCommon, err := repo.Commit(emptyTree, mainBranch, "Initial commit\n", false)
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.SetReference(featureBranch, cCommon); err != nil {
			t.Fatal(err)
		}

		cA, err := repo.Commit(treeA, mainBranch, "Test commit\n", false)
		if err != nil {
			t.Fatal(err)
		}

		cB, err := repo.Commit(treeB, featureBranch, "Test commit\n", false)
		if err != nil {
			t.Fatal(err)
		}

		// Create a merge commit with two parents and a different tree
		cM := repo.commitWithParents(t, treeC, []Hash{cA, cB}, "Merge commit\n", false)

		diffs, err := repo.GetFilePathsChangedByCommit(cM)
		assert.Nil(t, err)
		assert.Equal(t, []string{"a", "b", "c"}, diffs)
	})

	t.Run("merge commit with overlapping parent trees", func(t *testing.T) {
		treeA, err := treeBuilder.WriteTreeFromEntries([]TreeEntry{NewEntryBlob("a", blobIDs[0])})
		if err != nil {
			t.Fatal(err)
		}

		treeB, err := treeBuilder.WriteTreeFromEntries([]TreeEntry{NewEntryBlob("a", blobIDs[1])})
		if err != nil {
			t.Fatal(err)
		}

		treeC, err := treeBuilder.WriteTreeFromEntries([]TreeEntry{NewEntryBlob("a", blobIDs[2])})
		if err != nil {
			t.Fatal(err)
		}

		mainBranch := testNameToRefName(t.Name())
		featureBranch := testNameToRefName(t.Name() + " feature branch")

		// Write common commit for both branches
		cCommon, err := repo.Commit(emptyTree, mainBranch, "Initial commit\n", false)
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.SetReference(featureBranch, cCommon); err != nil {
			t.Fatal(err)
		}

		cA, err := repo.Commit(treeA, mainBranch, "Test commit\n", false)
		if err != nil {
			t.Fatal(err)
		}

		cB, err := repo.Commit(treeB, featureBranch, "Test commit\n", false)
		if err != nil {
			t.Fatal(err)
		}

		// Create a merge commit with two parents and an overlapping tree
		cM := repo.commitWithParents(t, treeC, []Hash{cA, cB}, "Merge commit\n", false)

		diffs, err := repo.GetFilePathsChangedByCommit(cM)
		assert.Nil(t, err)
		assert.Equal(t, []string{"a"}, diffs)
	})
}

func TestGetFilePathsChangedSinceLastCommit(t *testing.T) {
	tmpDir := t.TempDir()
	repo := CreateTestGitRepository(t, tmpDir, false)

	treeBuilder := NewTreeBuilder(repo)

	blobID, err := repo.WriteBlob([]byte(fmt.Sprintf("test_data")))
	if err != nil {
		t.Fatal(err)
	}

	treeHash, err := treeBuilder.WriteTreeFromEntries([]TreeEntry{NewEntryBlob("a", blobID)})
	if err != nil {
		t.Fatal(err)
	}

	_, err = repo.Commit(treeHash, "refs/heads/main", "Test commit\n", false)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("include staged", func(t *testing.T) {
		paths, err := repo.GetFilePathsChangedSinceLastCommit(true)
		assert.Nil(t, err)
		assert.Len(t, paths, 1)
		assert.Equal(t, "a", paths[0])

		err = os.WriteFile(filepath.Join(tmpDir, "test_file"), []byte("test_data"), 0644)
		require.Nil(t, err)

		paths, err = repo.GetFilePathsChangedSinceLastCommit(true)
		assert.Nil(t, err)
		assert.Len(t, paths, 1)
		assert.Equal(t, "a", paths[0])

		_, err = repo.executor("add", "test_file").executeString()
		require.Nil(t, err)

		paths, err = repo.GetFilePathsChangedSinceLastCommit(true)
		assert.Nil(t, err)
		assert.Len(t, paths, 1)
		assert.Equal(t, "test_file", paths[0])
	})

	t.Run("exclude staged", func(t *testing.T) {
		paths, err := repo.GetFilePathsChangedSinceLastCommit(false)
		assert.Nil(t, err)
		assert.Nil(t, paths)
	})
}
