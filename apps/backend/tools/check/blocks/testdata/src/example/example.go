package example

import (
	"errors"
	"strconv"
)

func operations(a, b string) (int, error) {
	x, err := strconv.Atoi(a)
	if err != nil {
		return 0, err
	}
	y, err := strconv.Atoi(b) // want `separated by an empty line`
	if err != nil {
		return 0, err
	}
	return x + y, nil // want `separated by an empty line`
}

func grouped(m map[string]int) map[int]string {
	out := map[int]string{}
	for key, value := range m {
		out[value] = key
	}
	return out
}

func plain() int {
	a := 1
	b := 2
	c := a + b
	return c
}

func controls(n int) error {
	if n > 1 {
		return errors.New("big")
	}
	for range n { // want `separated by an empty line`
	}
	return nil // want `separated by an empty line`
}

func comment(a string) error {
	_, err := strconv.Atoi(a)
	if err != nil {
		return err
	}
	// The second parse.
	_, err = strconv.Atoi(a) // want `separated by an empty line`
	return err
}

func filled(kind string) error {
	var err error
	switch kind {
	case "a":
		err = errors.New("a")
	default:
		err = errors.New("other")
	}
	return err
}

type writer interface {
	write(a string, b int) (string, error)
}

func multiline(w writer, items []string) ([]string, error) {
	var out []string
	for _, item := range items {
		result, err := w.write(item,
			1)
		if err != nil {
			return nil, err
		}

		out = append(out, result)
	}
	return out, nil
}
