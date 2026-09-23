package tools

import (
	"context"
)

type SourceRouter struct {
	Event   Adapter
	Context Adapter
}

func (r SourceRouter) Query(ctx context.Context, spec Spec, args map[string]any, invocation InvocationContext) (AdapterResult, *ToolError) {
	if len(spec.EventKinds) > 0 && r.Event != nil {
		return r.Event.Query(ctx, spec, args, invocation)
	}
	if r.Context != nil {
		return r.Context.Query(ctx, spec, args, invocation)
	}
	return AdapterResult{}, reject(ErrSourceUnavailable, "", "数据源能力未配置", false)
}
