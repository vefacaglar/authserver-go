package domain

const (
	DefaultPage     = 1
	DefaultPageSize = 50
	MaxPageSize     = 500
)

type PagedRequest struct {
	Page     int
	PageSize int
}

func (r PagedRequest) Normalized() PagedRequest {
	if r.Page < 1 {
		r.Page = DefaultPage
	}
	if r.PageSize < 1 {
		r.PageSize = DefaultPageSize
	}
	if r.PageSize > MaxPageSize {
		r.PageSize = MaxPageSize
	}
	return r
}

type PagedResult[T any] struct {
	Items      []T
	TotalCount int
	Page       int
	PageSize   int
}
