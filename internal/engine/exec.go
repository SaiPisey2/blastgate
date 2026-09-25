package engine

import "github.com/SaiPisey2/blastgate/internal/normalize"

func assessExec(a normalize.Action) Impact {
	return Unmeasured("an arbitrary command in a container cannot be measured")
}
