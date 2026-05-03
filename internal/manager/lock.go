package manager

import "sync"

type keyLock struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func newKeyLock() *keyLock {
	return &keyLock{locks: make(map[string]*sync.Mutex)}
}

func (k *keyLock) lock(key string) func() {
	k.mu.Lock()

	l, ok := k.locks[key]
	if !ok {
		l = &sync.Mutex{}
		k.locks[key] = l
	}

	k.mu.Unlock()
	l.Lock()

	return l.Unlock
}
