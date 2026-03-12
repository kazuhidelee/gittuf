// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package gitinterface

func (r *Repository) InvokeGarbageCollector(aggressive bool) error {
	if aggressive {
		_, err := r.executor("-c", "gc.reflogExpire=0", "-c", "gc.reflogExpireUnreachable=0", "-c", "gc.rerereresolved=0", "-c", "gc.rerereunresolved=0", "-c", "gc.pruneExpire=now", "gc").executeString()
		return err
	}
	_, err := r.executor("gc").executeString()
	return err
}
