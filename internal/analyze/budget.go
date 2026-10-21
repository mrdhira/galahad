package analyze

import "context"

type budgetKey struct{}

// WithBudget returns a context that tells analyzers how many bytes of the job
// budget are left. A negative n counts as zero.
func WithBudget(ctx context.Context, n int64) context.Context {
	return context.WithValue(ctx, budgetKey{}, max(n, 0))
}

// Budget returns the bytes of the job budget left, and false when the context
// carries none. An analyzer takes the smaller of this and its own cap.
func Budget(ctx context.Context) (int64, bool) {
	n, ok := ctx.Value(budgetKey{}).(int64)
	return n, ok
}

// Priority is implemented by an analyzer that must see some files even when the
// job is past its file cap or byte budget. The path is the clean path of a file
// on disk, relative to the target.
type Priority interface {
	Priority(path string) bool
}
