package es

// Paginator selects one page of a list by the number of records to skip and the number of records to return.
// [BatchReader.ReadAll] takes a Paginator to limit its result.
type Paginator interface {
	// Offset returns the number of records to skip before the page starts.
	Offset() uint64

	// Limit returns the largest number of records on the page.
	Limit() uint64
}

var _ Paginator = PageNumberPagination{}

// DefaultPaginator is a [Paginator] that selects the first page of 100 records.
var DefaultPaginator = PageNumberPagination{}

// PageNumberPagination is a [Paginator] that selects a page by its number and size.
//
// A zero Page selects the first page. A zero PageSize, or one above 1000, selects 100 records, so a caller cannot ask
// for an unbounded list.
type PageNumberPagination struct {
	// Page is the page number, counted from 1.
	Page uint64

	// PageSize is the number of records on a page, from 1 to 1000.
	PageSize uint64
}

// Offset returns the number of records before the selected page.
func (p PageNumberPagination) Offset() uint64 {
	page := p.Page
	if page == 0 {
		page = 1
	}

	return (page - 1) * p.Limit()
}

// Limit returns the number of records on the selected page, after the default size and the upper bound apply.
func (p PageNumberPagination) Limit() uint64 {
	size := p.PageSize
	if size == 0 || size > 1000 {
		size = 100
	}

	return size
}
