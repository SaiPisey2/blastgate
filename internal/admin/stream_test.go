package admin

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/SaiPisey2/blastgate/internal/engine"
	"github.com/SaiPisey2/blastgate/internal/store"
)

// sseEvent is one event as a browser's EventSource would dispatch it. A
// comment line (the heartbeat) arrives as name ":" with the comment text
// as data. dataLines counts the data: lines, so a test can see that a
// JSON payload never spilled onto a second line.
type sseEvent struct {
	id        string
	name      string
	data      string
	dataLines int
}

// fastStream makes the stream poll and beat quickly for one test and
// restores the defaults after. It must run before the fixture starts its
// server, so the restore (registered first) runs after the server closes.
func fastStream(t *testing.T, poll, beat time.Duration) {
	t.Helper()
	oldPoll, oldBeat := streamPoll, streamHeartbeat
	streamPoll, streamHeartbeat = poll, beat
	t.Cleanup(func() { streamPoll, streamHeartbeat = oldPoll, oldBeat })
}

// openStream sends GET /api/stream as c. On 200 the events are read on a
// goroutine into the returned channel, which is closed when the server
// ends the stream. Closing the response body is the browser leaving.
func openStream(t *testing.T, c *client) (*http.Response, <-chan sseEvent) {
	t.Helper()
	return openStreamFrom(t, c, "")
}

// openStreamFrom is openStream sending lastEventID as Last-Event-ID, as a
// browser's EventSource does when it reconnects ("" sends none).
func openStreamFrom(t *testing.T, c *client, lastEventID string) (*http.Response, <-chan sseEvent) {
	t.Helper()
	// A stream whose headers never arrive (nothing flushed) must fail the
	// test, not hang it: Do waits for headers with no timeout of its own.
	ctx, cancel := context.WithCancel(context.Background())
	timer := time.AfterFunc(3*time.Second, cancel)
	req, _ := http.NewRequestWithContext(ctx, "GET", c.f.srv.URL+"/api/stream", nil)
	req.Header.Set("Cookie", SessionCookie+"="+c.cookie)
	if lastEventID != "" {
		req.Header.Set("Last-Event-ID", lastEventID)
	}
	resp, err := c.f.httpClient().Do(req)
	timer.Stop()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close(); cancel() })
	ch := make(chan sseEvent, 4096)
	if resp.StatusCode != 200 {
		close(ch)
		return resp, ch
	}
	go func() {
		defer close(ch)
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
		var ev sseEvent
		var data []string
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if ev.name != "" || len(data) > 0 {
					ev.data, ev.dataLines = strings.Join(data, "\n"), len(data)
					ch <- ev
				}
				ev, data = sseEvent{}, nil
			case strings.HasPrefix(line, ":"):
				ch <- sseEvent{name: ":", data: strings.TrimSpace(line[1:])}
			case strings.HasPrefix(line, "id: "):
				ev.id = line[len("id: "):]
			case strings.HasPrefix(line, "event: "):
				ev.name = line[len("event: "):]
			case strings.HasPrefix(line, "data: "):
				data = append(data, line[len("data: "):])
			}
		}
	}()
	return resp, ch
}

// next returns the next event that is not a heartbeat.
func next(t *testing.T, ch <-chan sseEvent, within time.Duration) sseEvent {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatal("stream ended")
			}
			if ev.name != ":" {
				return ev
			}
		case <-deadline:
			t.Fatalf("no event within %v", within)
		}
	}
}

// ended waits for the server to close the stream.
func ended(t *testing.T, ch <-chan sseEvent, within time.Duration) {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if ev.name != ":" {
				t.Fatalf("event %q after the stream should have ended", ev.name)
			}
		case <-deadline:
			t.Fatalf("stream still open after %v", within)
		}
	}
}

func (f *apiFixture) slots() (total int, per map[string]int) {
	f.api.slots.mu.Lock()
	defer f.api.slots.mu.Unlock()
	return f.api.slots.total, copyCounts(f.api.slots.per)
}

func copyCounts(m map[string]int) map[string]int {
	out := map[string]int{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

// waitSlots waits until no stream holds a slot: the handler releases
// after it returns, a moment after the client sees the stream end.
func (f *apiFixture) waitSlots(t *testing.T, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		total, per := f.slots()
		if total == 0 && len(per) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("slots still held: total %d, per session %v", total, per)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func appendRow(t *testing.T, f *apiFixture, id string) {
	t.Helper()
	r := decisionRow(f.clock.Now(), id, "safe", "allow", engine.Impact{Class: engine.ClassReversible, Measured: true, Undo: "recreate"})
	if err := f.st.AppendAudit(context.Background(), r); err != nil {
		t.Fatal(err)
	}
}

func TestStreamSendsNewAuditRows(t *testing.T) {
	fastStream(t, 20*time.Millisecond, time.Hour)
	f := newAPIFixture(t)
	appendRow(t, f, "before")
	c := f.signIn(t, "carol")
	resp, ch := openStream(t, c)
	if resp.StatusCode != 200 {
		t.Fatalf("stream: %d", resp.StatusCode)
	}
	hello := decode[map[string]int64](t, next(t, ch, 3*time.Second).data)
	next(t, ch, 3*time.Second) // the first approvals event
	appendRow(t, f, "after")
	ev := next(t, ch, 3*time.Second)
	if ev.name != "audit" {
		t.Fatalf("got %q %s, want an audit event", ev.name, ev.data)
	}
	row := decode[map[string]any](t, ev.data)
	// The row already there at connect is history the feed fetched; only
	// the new one is streamed.
	if row["request_id"] != "after" || int64(row["id"].(float64)) <= hello["last_id"] {
		t.Errorf("streamed %v after hello %v", row, hello)
	}
}

// TestStreamEventsAreWhatTheUIParses pins the wire format ui/src/api.ts
// reads: event names, one JSON line of data each, hello first, then the
// pending approvals, then audit rows as FeedRow; approvals again only
// when the pending set changes; heartbeats as comments.
func TestStreamEventsAreWhatTheUIParses(t *testing.T) {
	fastStream(t, 10*time.Millisecond, 30*time.Millisecond)
	f := newAPIFixture(t)
	f.pending(t, approvalID)
	c := f.signIn(t, "carol")
	resp, ch := openStream(t, c)
	if resp.StatusCode != 200 {
		t.Fatalf("stream: %d", resp.StatusCode)
	}
	for k, want := range map[string]string{"Content-Type": "text/event-stream", "Cache-Control": "no-store", "X-Accel-Buffering": "no"} {
		if got := resp.Header.Get(k); got != want {
			t.Errorf("%s: %q, want %q", k, got, want)
		}
	}

	hello := next(t, ch, 3*time.Second)
	if hello.name != "hello" || hello.dataLines != 1 || keys(t, hello.data) != "last_id" {
		t.Errorf("hello: %+v", hello)
	}
	ap := next(t, ch, 3*time.Second)
	if ap.name != "approvals" || ap.data != `{"count":1,"ids":["`+approvalID+`"]}` {
		t.Errorf("first approvals: %+v", ap)
	}

	// A stored action pretty-printed across lines must still be one data
	// line: a second line would be joined with "\n" by the browser, and a
	// line starting "event:" inside it would forge an event.
	r := decisionRow(f.clock.Now(), "pretty", "safe", "allow", engine.Impact{Class: engine.ClassReversible, Measured: true})
	r.ActionJSON = []byte("{\n  \"verb\": \"delete\",\n  \"name\": \"x\\nevent: expired\"\n}")
	if err := f.st.AppendAudit(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	ev := next(t, ch, 3*time.Second)
	if ev.name != "audit" || ev.dataLines != 1 {
		t.Fatalf("audit: %+v", ev)
	}
	row := decode[map[string]any](t, ev.data)
	for _, k := range []string{"id", "at", "kind", "request_id", "session", "human", "agent", "source", "verb", "group",
		"resource", "subresource", "namespace", "name", "request_digest", "class", "measured", "rule", "decision",
		"approval_id", "status", "outcome", "latency_ms", "snapshot", "action", "impact", "labels"} {
		if _, ok := row[k]; !ok {
			t.Errorf("audit row lacks %q: %v", k, keysOf(row))
		}
	}
	if _, err := time.Parse(time.RFC3339, row["at"].(string)); err != nil {
		t.Errorf("at is not RFC3339: %v", row["at"])
	}
	if _, ok := row["id"].(float64); !ok {
		t.Errorf("id is not a number: %v", row["id"])
	}

	// Nothing changed: only heartbeats for several polls, no repeated
	// approvals event.
	deadline := time.After(120 * time.Millisecond)
	pings := 0
quiet:
	for {
		select {
		case ev := <-ch:
			if ev.name != ":" || ev.data != "ping" {
				t.Fatalf("unexpected event while nothing changed: %+v", ev)
			}
			pings++
		case <-deadline:
			break quiet
		}
	}
	if pings == 0 {
		t.Error("no heartbeat in 120ms with a 30ms period")
	}

	// A new pending approval: the set changes, ids come sorted.
	second := "00000000000000000000000000000001"
	f.pending(t, second)
	ap = next(t, ch, 3*time.Second)
	if ap.name != "approvals" || ap.data != `{"count":2,"ids":["`+second+`","`+approvalID+`"]}` {
		t.Errorf("after a second hold: %+v", ap)
	}
	// Deciding one takes it out; an empty queue is [] not null, which the
	// UI would otherwise read as "unknown".
	for _, id := range []string{second, approvalID} {
		if code, body := c.post(t, "/api/approvals/"+id+"/deny", ""); code != 200 {
			t.Fatalf("deny: %d %s", code, body)
		}
	}
	for {
		ap = next(t, ch, 3*time.Second)
		if ap.name == "approvals" && ap.data == `{"count":0,"ids":[]}` {
			break
		}
		if ap.name != "approvals" {
			t.Fatalf("unexpected %+v", ap)
		}
	}
}

func keys(t *testing.T, data string) string {
	t.Helper()
	return strings.Join(keysOf(decode[map[string]any](t, data)), ",")
}

// A burst bigger than one AuditAfter page is drained in the same poll,
// but one poll stops at the per-tick cap and leaves the rest for the next.
func TestStreamCatchesUpInOnePollUpToTheCap(t *testing.T) {
	fastStream(t, time.Hour, time.Hour) // only the poll right after hello runs
	oldBatch, oldCap := streamBatch, streamCatchUp
	streamBatch, streamCatchUp = 2, 5
	t.Cleanup(func() { streamBatch, streamCatchUp = oldBatch, oldCap })
	f := newAPIFixture(t)
	c := f.signIn(t, "carol")
	f.cs.mu.Lock()
	f.cs.onAuditAfter = func() {
		for i := range 7 {
			appendRow(t, f, fmt.Sprintf("burst-%d", i))
		}
	}
	f.cs.mu.Unlock()
	_, ch := openStream(t, c)
	if ev := next(t, ch, 3*time.Second); ev.name != "hello" {
		t.Fatalf("got %+v", ev)
	}
	var got []string
	deadline := time.After(300 * time.Millisecond)
collect:
	for {
		select {
		case ev := <-ch:
			if ev.name == "audit" {
				got = append(got, decode[map[string]any](t, ev.data)["request_id"].(string))
			}
		case <-deadline:
			break collect
		}
	}
	want := []string{"burst-0", "burst-1", "burst-2", "burst-3", "burst-4"}
	if !slices.Equal(got, want) {
		t.Errorf("one poll streamed %v, want %v", got, want)
	}
}

func TestStreamEndsWhenSessionRevoked(t *testing.T) {
	cases := map[string]func(t *testing.T, f *apiFixture, c *client){
		"logout": func(t *testing.T, f *apiFixture, c *client) {
			if code, body := c.post(t, "/api/logout", ""); code != 204 {
				t.Fatalf("logout: %d %s", code, body)
			}
		},
		// Only the approver row: RevokeApprover would also revoke the
		// session and so never reach the ApproverRevoked check. This is
		// the state a login racing RevokeApprover's sweep leaves behind.
		"approver revoked, session not": func(t *testing.T, f *apiFixture, c *client) {
			db, err := sql.Open("sqlite", "file:"+f.dbPath+"?_pragma=busy_timeout(5000)")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec(`UPDATE approvers SET revoked_at = ? WHERE id = ?`, f.clock.Now().UnixMilli(), "ap-"+c.name); err != nil {
				t.Fatal(err)
			}
		},
		"session expired": func(t *testing.T, f *apiFixture, c *client) {
			f.clock.Add(SessionTTL)
		},
	}
	for name, end := range cases {
		t.Run(name, func(t *testing.T) {
			fastStream(t, 20*time.Millisecond, time.Hour)
			f := newAPIFixture(t)
			c := f.signIn(t, "carol")
			_, ch := openStream(t, c)
			next(t, ch, 3*time.Second) // hello
			next(t, ch, 3*time.Second) // approvals
			end(t, f, c)
			ev := next(t, ch, 3*time.Second)
			// With no data line a browser's EventSource drops the event
			// without dispatching it, and the UI would never sign out.
			if ev.name != "expired" || ev.dataLines != 1 {
				t.Fatalf("got %+v, want an expired event with data", ev)
			}
			ended(t, ch, 3*time.Second)
			f.waitSlots(t, 3*time.Second)
		})
	}
}

// streamCode opens a stream and returns its status, keeping it open (on
// 200) until the test ends or close is called.
func streamCode(t *testing.T, c *client) (int, string, func()) {
	t.Helper()
	resp, _ := openStream(t, c)
	if resp.StatusCode != 200 {
		defer resp.Body.Close()
		return resp.StatusCode, readBody(t, resp) + " " + resp.Header.Get("Content-Type"), func() {}
	}
	return 200, "", func() { resp.Body.Close() }
}

// sessionFor makes a signed-in client straight in the store. Past five
// logins from one address the login limiter answers 429, and this test
// needs nine sessions.
func sessionFor(t *testing.T, f *apiFixture, name string) *client {
	t.Helper()
	ctx := context.Background()
	_, h := NewLoginToken()
	if err := f.st.CreateApprover(ctx, store.Approver{ID: "ap-" + name, Name: name, Created: f.clock.Now()}, h); err != nil {
		t.Fatal(err)
	}
	id, csrf := randomString(), randomString()
	u := store.UISession{ApproverID: "ap-" + name, ApproverName: name, CSRF: csrf, Created: f.clock.Now(), Expires: f.clock.Now().Add(SessionTTL)}
	if err := f.st.CreateUISession(ctx, u, hashOf(id)); err != nil {
		t.Fatal(err)
	}
	return &client{f: f, cookie: id, csrf: csrf, name: name}
}

func TestStreamLimits(t *testing.T) {
	// No polling: 32 streams polling every few milliseconds starve the
	// server on one CPU under -race, and slots do not depend on polls.
	fastStream(t, time.Hour, time.Hour)
	f := newAPIFixture(t)
	want429 := `{"error":"too many live streams"} application/json`

	a := sessionFor(t, f, "a")
	var closeA []func()
	for i := range 4 {
		code, body, cl := streamCode(t, a)
		if code != 200 {
			t.Fatalf("stream %d of one session: %d %s", i+1, code, body)
		}
		closeA = append(closeA, cl)
	}
	if code, body, _ := streamCode(t, a); code != 429 || body != want429 {
		t.Errorf("5th stream of one session: %d %s", code, body)
	}

	// Seven more sessions bring the total to 32.
	for i := range 7 {
		c := sessionFor(t, f, fmt.Sprintf("s%d", i))
		for j := range 4 {
			if code, body, _ := streamCode(t, c); code != 200 {
				t.Fatalf("session %d stream %d: %d %s", i, j+1, code, body)
			}
		}
	}
	if total, _ := f.slots(); total != 32 {
		t.Fatalf("total %d, want 32", total)
	}
	fresh := sessionFor(t, f, "fresh")
	if code, body, _ := streamCode(t, fresh); code != 429 || body != want429 {
		t.Errorf("33rd stream overall: %d %s", code, body)
	}

	// One of a's streams leaves; its slot, and only its slot, comes back.
	closeA[0]()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if total, _ := f.slots(); total == 31 {
			break
		}
		if time.Now().After(deadline) {
			total, per := f.slots()
			t.Fatalf("slot not freed: total %d %v", total, per)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if code, body, _ := streamCode(t, a); code != 200 {
		t.Errorf("a stream after one left: %d %s", code, body)
	}
	if code, body, _ := streamCode(t, fresh); code != 429 || body != want429 {
		t.Errorf("past 32 again: %d %s", code, body)
	}
}

func TestStreamSlotsFreeWhenTheClientLeaves(t *testing.T) {
	// No polling: 32 streams polling every few milliseconds starve the
	// server on one CPU under -race, and slots do not depend on polls.
	fastStream(t, time.Hour, time.Hour)
	f := newAPIFixture(t)
	a := f.signIn(t, "a")
	for round := range 3 {
		var closers []func()
		for i := range 4 {
			code, body, cl := streamCode(t, a)
			if code != 200 {
				t.Fatalf("round %d stream %d: %d %s", round, i+1, code, body)
			}
			closers = append(closers, cl)
		}
		for _, cl := range closers {
			cl()
		}
		f.waitSlots(t, 3*time.Second)
	}
}

// A client that connects and never reads must not hold its slot forever:
// once the socket buffers fill, a write blocks, and only a write deadline
// ends it.
func TestStreamDropsAClientThatNeverReads(t *testing.T) {
	fastStream(t, 10*time.Millisecond, time.Hour)
	old := streamWriteTimeout
	streamWriteTimeout = 100 * time.Millisecond
	t.Cleanup(func() { streamWriteTimeout = old })
	f := newAPIFixture(t)
	c := f.signIn(t, "carol")
	conn, err := net.Dial("tcp", strings.TrimPrefix(f.srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetReadBuffer(4 << 10)
	}
	fmt.Fprintf(conn, "GET /api/stream HTTP/1.1\r\nHost: x\r\nCookie: %s=%s\r\n\r\n", SessionCookie, c.cookie)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if total, _ := f.slots(); total == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stream never started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Big rows fill the socket buffers quickly.
	big := strings.Repeat("x", 256<<10)
	for i := range 64 {
		r := decisionRow(f.clock.Now(), fmt.Sprintf("big-%d", i), "safe", "allow", engine.Impact{Class: engine.ClassReversible, Measured: true})
		r.LabelsJSON, _ = json.Marshal(map[string]string{"pad": big})
		if err := f.st.AppendAudit(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
	f.waitSlots(t, 5*time.Second)
}

// auditIDs reads audit events until none arrives for a while, returning
// their request ids and checking each carries id: equal to its row id.
func auditIDs(t *testing.T, ch <-chan sseEvent, quiet time.Duration) []string {
	t.Helper()
	var got []string
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return got
			}
			if ev.name != "audit" {
				continue
			}
			row := decode[map[string]any](t, ev.data)
			if ev.id != fmt.Sprint(int64(row["id"].(float64))) {
				t.Errorf("event id %q, row id %v", ev.id, row["id"])
			}
			got = append(got, row["request_id"].(string))
		case <-time.After(quiet):
			return got
		}
	}
}

// A browser that reconnects sends the id of the last event it saw; the
// stream resumes after it, so rows written while it was away are not lost
// (P2-R24). Anything that is not an id the table could have produced
// falls back to "from now", as a fresh connect does.
func TestStreamResumesFromLastEventID(t *testing.T) {
	fastStream(t, 10*time.Millisecond, time.Hour)
	f := newAPIFixture(t)
	c := f.signIn(t, "carol")
	for i := range 3 {
		appendRow(t, f, fmt.Sprintf("old-%d", i))
	}
	rows, _ := f.st.AuditPage(context.Background(), store.AuditFilter{Limit: 3})
	maxID, firstID := rows[0].ID, rows[2].ID

	// Resume after the first row: the other two are replayed, in order,
	// and hello reports the cursor the stream resumes from.
	// Each stream is closed before the next, and its slot awaited: one
	// session may hold only four.
	resp, ch := openStreamFrom(t, c, fmt.Sprint(firstID))
	hello := next(t, ch, 3*time.Second)
	if hello.name != "hello" || hello.id != fmt.Sprint(firstID) || decode[map[string]int64](t, hello.data)["last_id"] != firstID {
		t.Errorf("hello on resume: %+v, want last_id %d", hello, firstID)
	}
	if got := auditIDs(t, ch, 150*time.Millisecond); strings.Join(got, ",") != "old-1,old-2" {
		t.Errorf("resume replayed %v, want old-1,old-2", got)
	}
	resp.Body.Close()
	f.waitSlots(t, 3*time.Second)

	// 0 is a valid cursor: everything is replayed.
	resp, ch = openStreamFrom(t, c, "0")
	if got := auditIDs(t, ch, 150*time.Millisecond); strings.Join(got, ",") != "old-0,old-1,old-2" {
		t.Errorf("resume from 0 replayed %v", got)
	}
	resp.Body.Close()
	f.waitSlots(t, 3*time.Second)

	for _, bad := range []string{"abc", "-1", fmt.Sprint(maxID + 1), "+1", "1e3", "1 2", "0x1", "99999999999999999999"} {
		resp, ch := openStreamFrom(t, c, bad)
		hello := next(t, ch, 3*time.Second)
		if hello.id != fmt.Sprint(maxID) || decode[map[string]int64](t, hello.data)["last_id"] != maxID {
			t.Errorf("Last-Event-ID %q: hello %s, want last_id %d", bad, hello.data, maxID)
		}
		if got := auditIDs(t, ch, 60*time.Millisecond); len(got) != 0 {
			t.Errorf("Last-Event-ID %q replayed %v", bad, got)
		}
		resp.Body.Close()
		f.waitSlots(t, 3*time.Second)
	}
}

// TestStreamCountsOnlyLivePendingApprovals: the badge and "N waiting"
// come from this event, so a pending row past its expiry must leave it,
// including one that lapses while the stream is open (I1).
func TestStreamCountsOnlyLivePendingApprovals(t *testing.T) {
	fastStream(t, 10*time.Millisecond, time.Minute)
	f := newAPIFixture(t)
	now := f.clock.Now()
	const soon, later, gone = "11111111111111111111111111111111", "22222222222222222222222222222222", "33333333333333333333333333333333"
	f.pendingAt(t, soon, now.Add(-time.Minute), now.Add(time.Minute))
	f.pendingAt(t, later, now.Add(-time.Minute), now.Add(time.Hour))
	f.pendingAt(t, gone, now.Add(-2*time.Hour), now.Add(-time.Hour))
	c := f.signIn(t, "carol")
	_, ch := openStream(t, c)
	next(t, ch, 3*time.Second) // hello
	if ap := next(t, ch, 3*time.Second); ap.name != "approvals" || ap.data != `{"count":2,"ids":["`+soon+`","`+later+`"]}` {
		t.Errorf("first approvals: %+v", ap)
	}
	f.clock.Add(2 * time.Minute)
	if ap := next(t, ch, 3*time.Second); ap.name != "approvals" || ap.data != `{"count":1,"ids":["`+later+`"]}` {
		t.Errorf("after one lapsed: %+v", ap)
	}
}
