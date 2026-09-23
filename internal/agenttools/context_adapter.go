package tools

import (
	"context"
	"encoding/json"

	"sentinel/internal/agentdomain"
)

type AlertRepository interface {
	Alert(tenant, id string) (domain.Alert, error)
}

type AlertAdapter struct{ Repository AlertRepository }

func (a AlertAdapter) Query(_ context.Context, _ Spec, args map[string]any, invocation InvocationContext) (AdapterResult, *ToolError) {
	ref, _ := args["alert_ref"].(string)
	alert, err := a.Repository.Alert(invocation.Scope.TenantID, ref)
	if err != nil {
		return AdapterResult{}, reject(ErrSourceUnavailable, "alert_ref", "告警不存在或不可用", false)
	}
	return AdapterResult{Status: StatusOK, Data: map[string]any{"alert": alert}, EntityRefs: []string{alert.ID},
		Coverage: Coverage{QueryComplete: true, TelemetryState: "COMPLETE", Source: "alerts", Warnings: []string{}}}, nil
}

type EntityContextAdapter struct{}

func (EntityContextAdapter) Query(_ context.Context, spec Spec, args map[string]any, invocation InvocationContext) (AdapterResult, *ToolError) {
	var ref string
	for name := range spec.Fields {
		if value, ok := args[name].(string); ok {
			ref = value
			break
		}
	}
	entity, ok := invocation.Entities.Resolve(ref)
	if !ok {
		return AdapterResult{}, reject(ErrUnknownEntity, "", "实体不存在", false)
	}
	var attributes map[string]any
	if len(entity.Attributes) > 0 && json.Unmarshal(entity.Attributes, &attributes) != nil {
		return AdapterResult{}, reject(ErrResultSchemaInvalid, "", "实体属性损坏", false)
	}
	return AdapterResult{Status: StatusOK, Data: map[string]any{"entity": entity, "attributes": attributes}, EntityRefs: []string{entity.ID},
		Coverage: Coverage{QueryComplete: true, TelemetryState: "COMPLETE", Source: spec.Source, Warnings: []string{}}}, nil
}

type TelemetryAdapter struct{}

func (TelemetryAdapter) Query(_ context.Context, _ Spec, _ map[string]any, _ InvocationContext) (AdapterResult, *ToolError) {
	return AdapterResult{Status: StatusPartial, Data: map[string]any{"ring_buffer_loss": "UNKNOWN", "upload_policy": "CONFIGURED", "retention": "MEMORY_ONLY"},
		Coverage: Coverage{QueryComplete: false, TelemetryState: "UNKNOWN", Source: "telemetry", Warnings: []string{"尚未接入持久化传感器健康指标"}}}, nil
}
