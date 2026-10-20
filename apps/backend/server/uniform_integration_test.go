//go:build integration

package server

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tidwall/gjson"
)

// jsonShape returns the sorted paths of the members of a JSON document, with the position of array items left out. Two
// documents with the same shape have the same members and the same nesting, whatever their values.
func jsonShape(value gjson.Result, prefix string, paths map[string]struct{}) {
	switch {
	case value.IsObject():
		value.ForEach(func(key, member gjson.Result) bool {
			path := prefix + "." + key.String()
			paths[path] = struct{}{}
			jsonShape(member, path, paths)

			return true
		})
	case value.IsArray():
		value.ForEach(func(_, item gjson.Result) bool {
			jsonShape(item, prefix+"[]", paths)

			return true
		})
	}
}

func shapeOf(data []byte) string {
	paths := map[string]struct{}{}
	jsonShape(gjson.ParseBytes(data), "", paths)

	list := make([]string, 0, len(paths))
	for path := range paths {
		list = append(list, path)
	}

	sort.Strings(list)

	return strings.Join(list, "\n")
}

// TestPasskeyOptionsDoNotRevealAccounts proves that the start of a passkey login gives the same status and the same
// response shape for an account with a passkey, an account without one and an unknown address, and that the fake list
// of credentials for an unknown address is deterministic, so asking twice does not show that the address is unknown.
func TestPasskeyOptionsDoNotRevealAccounts(t *testing.T) {
	s := newStand(t)
	withPasskey := fmt.Sprintf("with-%d@example.com", time.Now().UnixNano())
	without := fmt.Sprintf("without-%d@example.com", time.Now().UnixNano())
	unknown := fmt.Sprintf("unknown-%d@example.com", time.Now().UnixNano())

	first := s.open()
	s.register(first.Handle, withPasskey)
	if _, a := s.enrollPasskey(first.Handle, s.authenticator(), "key"); a.Error != nil {
		t.Fatalf("enroll: %+v", a.Error)
	}

	second := s.open()
	s.register(second.Handle, without)

	start := func(email string) apiResponse {
		a := s.call(http.MethodPost, "/v1/auth/passkey", s.open().Handle, map[string]string{"email": email})
		if a.Error != nil || a.Status != http.StatusOK {
			t.Fatalf("passkey options for %s: %d %+v", email, a.Status, a.Error)
		}

		return a
	}

	real, empty, fake := start(withPasskey), start(without), start(unknown)

	// Same status and same shape, whether the account has a passkey, has none or does not exist.
	for name, a := range map[string]apiResponse{"an account without a passkey": empty, "an unknown address": fake} {
		if a.Status != real.Status {
			t.Fatalf("%s: status %d, want %d", name, a.Status, real.Status)
		}

		if got, want := shapeOf(a.Data), shapeOf(real.Data); got != want {
			t.Fatalf("%s: the response shape differs\n got:\n%s\nwant:\n%s", name, got, want)
		}

		list := gjson.GetBytes(a.Data, "publicKey.allowCredentials").Array()
		if len(list) == 0 || list[0].Get("id").String() == "" || list[0].Get("type").String() != "public-key" {
			t.Fatalf("%s: the credential list must look like a real one: %s", name, a.Data)
		}
	}

	// The fake list does not change between two asks, and another address gets another list.
	again := start(unknown)
	if gjson.GetBytes(again.Data, "publicKey.allowCredentials").Raw != gjson.GetBytes(fake.Data, "publicKey.allowCredentials").Raw {
		t.Fatal("the fake credential list of one address must not change")
	}

	other := start("another-" + unknown)
	if gjson.GetBytes(other.Data, "publicKey.allowCredentials").Raw == gjson.GetBytes(fake.Data, "publicKey.allowCredentials").Raw {
		t.Fatal("two unknown addresses must get two lists")
	}
}
