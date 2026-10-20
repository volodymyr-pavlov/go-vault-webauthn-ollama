package web

import "sync"

// Pool is a typed pool of reusable *T values, backed by [sync.Pool]. The zero value is ready to use. A handler can keep
// the arguments of a request in a pool, so a request allocates no memory for them.
type Pool[T any] struct {
	pool sync.Pool
}

// Get returns a pooled value, or a new zero value if the pool is empty.
func (p *Pool[T]) Get() *T {
	value, ok := p.pool.Get().(*T)
	if !ok {
		return new(T)
	}

	return value
}

// Put sets *value to the zero value and returns it to the pool. The caller must not use value afterwards.
func (p *Pool[T]) Put(value *T) {
	var zero T
	*value = zero
	p.pool.Put(value)
}
