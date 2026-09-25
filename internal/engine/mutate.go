package engine

import (
	"context"

	"github.com/SaiPisey2/blastgate/internal/normalize"
)

func (e *Engine) assessMutation(ctx context.Context, a normalize.Action, body []byte) Impact {
	return Unmeasured("mutation scoring arrives with the dry-run engine")
}
