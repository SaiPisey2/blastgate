package admin

// This file is GET /api/stream: Server-Sent Events that keep the approver
// UI live. hello names the audit id the stream starts after: the newest
// at connect (everything up to it the feed fetched itself), or the
// browser's Last-Event-ID when it reconnects. After it come audit (one
// FeedRow per new row, its row id as the event id), approvals ({count, ids} of the pending queue, when it changes),
// a ": ping" comment as a heartbeat, and expired when the session ends.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/SaiPisey2/blastgate/internal/store"
)

// Vars, not consts, so a test can poll in milliseconds instead of waiting
// on the real clock.
var (
	streamPoll      = time.Second
	streamHeartbeat = 15 * time.Second
	// streamWriteTimeout bounds each write. A browser that stops reading
	// (a frozen tab, a dead laptop on a half-open connection) fills the
	// socket buffers and then blocks the write forever; the deadline turns
	// that into an error that ends the stream and frees its slot. Set
	// before each write and cleared after it, it also keeps a
	// listener-wide WriteTimeout from cutting a healthy stream off
	// mid-life. It is longer than the heartbeat, so even a deadline left
	// behind is renewed by the next ping before it can fire on an idle
	// stream (TestHeartbeatIsShorterThanTheWriteTimeout).
	streamWriteTimeout = 20 * time.Second
	// streamBatch is one AuditAfter page; streamCatchUp bounds how many
	// rows one poll sends, looping over pages, so a burst is drained
	// without waiting a second per page but one poll cannot run unbounded
	// behind a runaway agent.
	streamBatch   = 200
	streamCatchUp = 1000
)

const (
	// Each stream holds a goroutine and queries the store every poll. A
	// UI opens one per tab; four covers a few tabs, and the total bounds
	// what a handful of approvers (or one stolen cookie) can make the
	// gateway do per second.
	maxStreamsPerSession = 4
	maxStreams           = 32
	// streamPendingLimit bounds the pending list read each poll. Past it
	// the count shown is the limit: a queue that long is a fire whose
	// exact size does not change what the approver does next.
	streamPendingLimit = 500

	errStreams = "too many live streams"
)

// streamSlots counts live streams per UI session (keyed by the cookie's
// hash, never the cookie) and in total. The lock is only ever held to
// count, never across a write to a client.
type streamSlots struct {
	mu    sync.Mutex
	total int
	per   map[string]int
}

func (s *streamSlots) acquire(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.total >= maxStreams || s.per[key] >= maxStreamsPerSession {
		return false
	}
	s.total++
	s.per[key]++
	return true
}

func (s *streamSlots) release(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total--
	// Deleted at zero, so sessions that come and go do not pile up keys.
	if s.per[key]--; s.per[key] <= 0 {
		delete(s.per, key)
	}
}

// sse writes events to one client. Every write gets a fresh deadline and
// is flushed at once: an event sitting in a buffer is a feed that looks
// live and is not.
type sse struct {
	w  http.ResponseWriter
	rc *http.ResponseController
}

func (s *sse) write(b []byte) error {
	// A writer without deadlines (a wrapper that does not Unwrap) only
	// loses the protection against a client that never reads.
	if err := s.setDeadline(time.Now().Add(streamWriteTimeout)); err != nil {
		return err
	}
	if _, err := s.w.Write(b); err != nil {
		return err
	}
	if err := s.rc.Flush(); err != nil {
		return err
	}
	// The deadline covers the write and nothing after it. Over HTTP/2 it
	// is a timer on the whole stream that fires whether or not anything is
	// being written: left set, it resets an idle stream with
	// INTERNAL_ERROR one write timeout after the last event.
	return s.setDeadline(time.Time{})
}

func (s *sse) setDeadline(t time.Time) error {
	if err := s.rc.SetWriteDeadline(t); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	return nil
}

// event sends one named event, with an id line when id is not "". json.Marshal never emits a raw newline (it
// escapes them in strings and compacts embedded RawMessage), so the data
// is always one line: a stored action holding "\nevent: expired" cannot
// split into a second, forged event.
func (s *sse) event(name, id string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	msg := make([]byte, 0, len(b)+len(name)+len(id)+24)
	// Events without an id (approvals, expired) leave the browser's last
	// event id as it was, so it always names an audit position.
	if id != "" {
		msg = append(msg, "id: "+id+"\n"...)
	}
	msg = append(msg, "event: "+name+"\ndata: "...)
	msg = append(msg, b...)
	msg = append(msg, "\n\n"...)
	return s.write(msg)
}

// lastEventIDPattern is plain base-10 digits: strconv alone would also
// take a sign ("+5", "-0"), which no event this stream sent ever carried.
var lastEventIDPattern = regexp.MustCompile(`^[0-9]{1,19}$`)

// resumeCursor reads a Last-Event-ID header. Only an id this table could
// have handed out counts: 0 through the current newest id. Anything else
// (garbage, a negative, an id from the future or from another database)
// is ignored and the stream starts from now, as a fresh connect does; a
// far-future cursor would otherwise silence the feed until the table
// caught up to it.
func resumeCursor(h string, newest int64) (int64, bool) {
	if !lastEventIDPattern.MatchString(h) {
		return 0, false
	}
	n, err := strconv.ParseInt(h, 10, 64)
	if err != nil || n < 0 || n > newest {
		return 0, false
	}
	return n, true
}

type pendingEvent struct {
	Count int      `json:"count"`
	IDs   []string `json:"ids"`
}

func (h *api) stream(w http.ResponseWriter, r *http.Request, _ store.UISession) {
	// Require already found this cookie; the stream re-reads the session
	// by its hash every poll, since the session Require saw may be
	// revoked while the stream is open.
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errUnauthenticated)
		return
	}
	idHash := hashOf(c.Value)
	key := string(idHash)
	// Refused before any SSE header is written, so the browser sees a
	// plain JSON 429 rather than a stream that ends at once and retries.
	if !h.slots.acquire(key) {
		fail(w, http.StatusTooManyRequests, errStreams)
		return
	}
	defer h.slots.release(key)

	ctx := r.Context()
	newest, err := h.st.AuditPage(ctx, store.AuditFilter{Limit: 1})
	if err != nil {
		h.internal(w, "stream start", err)
		return
	}
	var lastID int64
	if len(newest) > 0 {
		lastID = newest[0].ID
	}
	// A reconnecting EventSource sends the id of the last event it got.
	// Resuming there keeps the rows written while it was away (P2-R24);
	// the per-poll cap still bounds how fast a far-back cursor catches up.
	if n, ok := resumeCursor(r.Header.Get("Last-Event-ID"), lastID); ok {
		lastID = n
	}
	poll, beat := streamPoll, streamHeartbeat

	hdr := w.Header()
	hdr.Set("Content-Type", "text/event-stream")
	hdr.Set("Cache-Control", "no-store")
	// A reverse proxy (nginx) that buffers responses would hold events
	// until its buffer filled.
	hdr.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	s := &sse{w: w, rc: http.NewResponseController(w)}
	// hello reports the cursor the stream starts from, and carries it as
	// the event id: a browser that reconnects before any audit row
	// arrives then still sends a Last-Event-ID, and nothing written in
	// between is lost.
	if s.event("hello", strconv.FormatInt(lastID, 10), map[string]int64{"last_id": lastID}) != nil {
		return
	}

	st := &streamState{h: h, s: s, idHash: idHash, lastID: lastID}
	// The first poll runs at once: the UI gets the pending queue right
	// after hello, and any row landed since hello is not a second late.
	if !st.poll(ctx) {
		return
	}
	pt := time.NewTicker(poll)
	defer pt.Stop()
	ht := time.NewTicker(beat)
	defer ht.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-pt.C:
			if !st.poll(ctx) {
				return
			}
		case <-ht.C:
			// A comment: EventSource ignores it, but it keeps idle
			// proxies from closing the connection and surfaces a dead
			// client as a write error.
			if s.write([]byte(": ping\n\n")) != nil {
				return
			}
		}
	}
}

// streamState is one stream's cursor. Each poll runs its queries to
// completion and keeps nothing open between polls, so an idle stream
// holds no database connection.
type streamState struct {
	h       *api
	s       *sse
	idHash  []byte
	lastID  int64
	pending []string
	sent    bool // whether an approvals event has been sent yet
}

// poll sends what changed since the last one. false ends the stream: the
// session is over, the client is gone, or the store failed (the browser
// reconnects on its own and starts from a fresh hello).
func (st *streamState) poll(ctx context.Context) bool {
	h := st.h
	u, err := h.auth.Store.UISessionByHash(ctx, st.idHash)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !h.auth.live(u)) {
		// data is required: EventSource drops an event with no data
		// line without dispatching it, and the UI would never sign out.
		st.s.event("expired", "", struct{}{})
		return false
	}
	if err != nil {
		return st.failed(ctx, "stream session lookup", err)
	}

	l, err := h.st.ListApprovalsLimit(ctx, "pending", streamPendingLimit)
	if err != nil {
		return st.failed(ctx, "stream pending approvals", err)
	}
	ids := make([]string, 0, len(l))
	for _, a := range l {
		ids = append(ids, a.ID)
	}
	slices.Sort(ids)
	if !st.sent || !slices.Equal(ids, st.pending) {
		if st.s.event("approvals", "", pendingEvent{Count: len(ids), IDs: ids}) != nil {
			return false
		}
		st.pending, st.sent = ids, true
	}

	for n := 0; n < streamCatchUp; {
		want := min(streamBatch, streamCatchUp-n)
		rows, err := h.st.AuditAfter(ctx, st.lastID, want)
		if err != nil {
			return st.failed(ctx, "stream audit", err)
		}
		for _, row := range rows {
			if st.s.event("audit", strconv.FormatInt(row.ID, 10), ToFeedRow(row)) != nil {
				return false
			}
			st.lastID = row.ID
		}
		n += len(rows)
		if len(rows) < want {
			break
		}
	}
	return true
}

// failed ends the stream on a store error, logging it unless the error is
// only the client having left mid-query.
func (st *streamState) failed(ctx context.Context, what string, err error) bool {
	if ctx.Err() == nil {
		st.h.log.Error("admin api: "+what, "err", err)
	}
	return false
}
