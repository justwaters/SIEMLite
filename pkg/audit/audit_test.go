package audit

import (
	"context"
	"testing"

	"siemlite/pkg/ingest"
	"siemlite/pkg/ocsf"
)

type capture struct{ fields map[string]string }

func (c *capture) SubmitWith(_ context.Context, _ *ocsf.Event, opts ingest.SubmitOptions) error {
	c.fields = opts.Fields
	return nil
}

type internalSource struct{}

func (internalSource) Builtin(context.Context, string) (int64, error) { return 4, nil }

// An entry's extra fields can't change its action: rules read the action to tell events apart.
func TestAnEntrysFieldsCannotChangeItsAction(t *testing.T) {
	c := &capture{}
	l := New(c, internalSource{}, nil)
	l.Record(context.Background(), Entry{Action: "signin", Message: "x", Fields: map[string]string{"action": "alert.closed", "target": "ann"}})
	if c.fields["action"] != "signin" || c.fields["target"] != "ann" {
		t.Errorf("fields = %v", c.fields)
	}
	l.Record(context.Background(), Entry{Action: "ingest.late", Message: "y"})
	if c.fields["action"] != "ingest.late" || len(c.fields) != 1 {
		t.Errorf("fields = %v", c.fields)
	}
}
