//go:build unix

package installer

import (
	"os/user"
	"testing"
)

func TestParseIDsRejectsMalformed(t *testing.T) {
	for _, u := range []*user.User{
		{Username: "x", Uid: "", Gid: "1"},
		{Username: "x", Uid: "abc", Gid: "1"},
		{Username: "x", Uid: "1", Gid: ""},
		{Username: "x", Uid: "1", Gid: "-1"},
	} {
		if _, _, err := parseIDs(u); err == nil {
			t.Errorf("parseIDs(%+v) = nil error, want an error", u)
		}
	}
	uid, gid, err := parseIDs(&user.User{Username: "x", Uid: "996", Gid: "995"})
	if err != nil || uid != 996 || gid != 995 {
		t.Errorf("parseIDs valid = %d, %d, %v", uid, gid, err)
	}
}
