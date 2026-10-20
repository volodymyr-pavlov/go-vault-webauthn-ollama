package example

type record struct{}

func (record) save() {}

func number() int { return 1 }

func hides() int {
	number := 2 // want `variable number hides the function of the package`
	return number
}

func parameter(record int) int { // want `variable record hides the type of the package`
	return record
}

func method() {
	save := 1 // want `variable save hides the method of the package`
	_ = save
}

func fine() int {
	value := number()
	return value
}
