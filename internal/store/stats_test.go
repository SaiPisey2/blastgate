package store

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"
)

func TestStatsBucketEveryStatusAndRespectTheWindow(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	since := t0
	n := 0
	seed := func(rule, status string, created time.Time) {
		t.Helper()
		n++
		a := appr(fmt.Sprintf("a%d", n))
		a.RequestDigest, a.Rule, a.Status, a.Created = a.ID, rule, status, created
		if err := s.CreateApproval(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	in := t0.Add(time.Minute)
	// rule "authority": every status once.
	for _, st := range []string{"pending", "partially_approved", "approved", "consumed", "superseded", "denied", "expired"} {
		seed("authority", st, in)
	}
	// rule "data-destruction": more held, so it sorts first.
	for _, st := range []string{"consumed", "consumed", "denied", "denied", "denied", "expired", "pending", "approved"} {
		seed("data-destruction", st, in)
	}
	// "quiet" and "zz-tie" hold the same number, so the name breaks the tie.
	seed("zz-tie", "denied", in)
	seed("zz-tie", "expired", in)
	seed("quiet", "consumed", in)
	// Created exactly at since: inside the window.
	seed("quiet", "approved", since)
	// Before the window: counted nowhere, and its rule does not appear.
	seed("authority", "approved", since.Add(-time.Millisecond))
	seed("old-only", "denied", since.Add(-time.Hour))

	got, err := s.PolicyStats(ctx, since)
	if err != nil {
		t.Fatal(err)
	}
	want := []RuleStats{
		{Rule: "data-destruction", Held: 8, Approved: 3, Denied: 3, Expired: 1},
		{Rule: "authority", Held: 7, Approved: 3, Denied: 1, Expired: 1},
		{Rule: "quiet", Held: 2, Approved: 2},
		{Rule: "zz-tie", Held: 2, Denied: 1, Expired: 1},
	}
	if !slices.Equal(got, want) {
		t.Errorf("stats =\n%+v\nwant\n%+v", got, want)
	}
	if got, err := s.PolicyStats(ctx, t0.Add(time.Hour)); err != nil || len(got) != 0 {
		t.Errorf("an empty window = %+v, %v", got, err)
	}
}
