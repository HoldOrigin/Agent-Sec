package domain

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type EventKind string

const (
	EventAlertCreated    EventKind = "ALERT_CREATED"
	EventSessionLogin    EventKind = "SESSION_LOGIN"
	EventSessionLogout   EventKind = "SESSION_LOGOUT"
	EventLoginSuccess    EventKind = "LOGIN_SUCCESS"
	EventLoginFailure    EventKind = "LOGIN_FAILURE"
	EventMFAChallenge    EventKind = "MFA_CHALLENGE"
	EventTokenIssue      EventKind = "TOKEN_ISSUE"
	EventKeyAuth         EventKind = "KEY_AUTH"
	EventAccountLock     EventKind = "ACCOUNT_LOCK"
	EventProcessFork     EventKind = "PROCESS_FORK"
	EventProcessExec     EventKind = "PROCESS_EXEC"
	EventProcessExit     EventKind = "PROCESS_EXIT"
	EventFileCreate      EventKind = "FILE_CREATE"
	EventFileWrite       EventKind = "FILE_WRITE"
	EventFileRename      EventKind = "FILE_RENAME"
	EventFileDelete      EventKind = "FILE_DELETE"
	EventFileChmod       EventKind = "FILE_CHMOD"
	EventFileChown       EventKind = "FILE_CHOWN"
	EventNetworkConnect  EventKind = "NETWORK_CONNECT"
	EventNetworkAccept   EventKind = "NETWORK_ACCEPT"
	EventNetworkClose    EventKind = "NETWORK_CLOSE"
	EventDNSQuery        EventKind = "DNS_QUERY"
	EventDNSResponse     EventKind = "DNS_RESPONSE"
	EventSetUID          EventKind = "SETUID"
	EventSetGID          EventKind = "SETGID"
	EventCapset          EventKind = "CAPSET"
	EventSudo            EventKind = "SUDO"
	EventSetNS           EventKind = "SETNS"
	EventUnshare         EventKind = "UNSHARE"
	EventMount           EventKind = "MOUNT"
	EventUmount          EventKind = "UMOUNT"
	EventChroot          EventKind = "CHROOT"
	EventPivotRoot       EventKind = "PIVOT_ROOT"
	EventPtrace          EventKind = "PTRACE"
	EventBPFLoad         EventKind = "BPF_LOAD"
	EventModuleLoad      EventKind = "MODULE_LOAD"
	EventContainerStart  EventKind = "CONTAINER_START"
	EventContainerStop   EventKind = "CONTAINER_STOP"
	EventContainerExec   EventKind = "CONTAINER_EXEC"
	EventHTTPRequest     EventKind = "HTTP_REQUEST"
	EventHTTPResponse    EventKind = "HTTP_RESPONSE"
	EventWAFDecision     EventKind = "WAF_DECISION"
	EventK8sAPIRequest   EventKind = "K8S_API_REQUEST"
	EventCloudAPIRequest EventKind = "CLOUD_API_REQUEST"
	EventSensorStatus    EventKind = "SENSOR_STATUS"
	EventDroppedEvents   EventKind = "DROPPED_EVENTS"
	EventUploadPolicy    EventKind = "UPLOAD_POLICY_CHANGE"
)

var knownEventKinds = map[EventKind]struct{}{
	EventAlertCreated: {}, EventSessionLogin: {}, EventSessionLogout: {}, EventLoginSuccess: {},
	EventLoginFailure: {}, EventMFAChallenge: {}, EventTokenIssue: {}, EventKeyAuth: {},
	EventAccountLock: {}, EventProcessFork: {}, EventProcessExec: {}, EventProcessExit: {},
	EventFileCreate: {}, EventFileWrite: {}, EventFileRename: {}, EventFileDelete: {},
	EventFileChmod: {}, EventFileChown: {}, EventNetworkConnect: {}, EventNetworkAccept: {},
	EventNetworkClose: {}, EventDNSQuery: {}, EventDNSResponse: {}, EventSetUID: {},
	EventSetGID: {}, EventCapset: {}, EventSudo: {}, EventSetNS: {}, EventUnshare: {},
	EventMount: {}, EventUmount: {}, EventChroot: {}, EventPivotRoot: {}, EventPtrace: {},
	EventBPFLoad: {}, EventModuleLoad: {}, EventContainerStart: {}, EventContainerStop: {},
	EventContainerExec: {}, EventHTTPRequest: {}, EventHTTPResponse: {}, EventWAFDecision: {},
	EventK8sAPIRequest: {}, EventCloudAPIRequest: {}, EventSensorStatus: {}, EventDroppedEvents: {},
	EventUploadPolicy: {},
}

type Outcome string

const (
	OutcomeSuccess Outcome = "SUCCESS"
	OutcomeFailure Outcome = "FAILURE"
	OutcomeAttempt Outcome = "ATTEMPT"
	OutcomeUnknown Outcome = "UNKNOWN"
)

type Event struct {
	ID            string          `json:"id"`
	SchemaVersion uint16          `json:"schema_version"`
	TenantID      string          `json:"tenant_id"`
	SensorID      string          `json:"sensor_id"`
	HostID        string          `json:"host_id"`
	BootID        string          `json:"boot_id"`
	ContainerID   string          `json:"container_id,omitempty"`
	CgroupID      uint64          `json:"cgroup_id,omitempty"`
	ProcessID     string          `json:"process_id,omitempty"`
	ParentProcess string          `json:"parent_process_id,omitempty"`
	SessionID     string          `json:"session_id,omitempty"`
	IdentityID    string          `json:"identity_id,omitempty"`
	Kind          EventKind       `json:"kind"`
	Outcome       Outcome         `json:"outcome"`
	ObservedAt    time.Time       `json:"observed_at"`
	IngestedAt    time.Time       `json:"ingested_at"`
	Details       json.RawMessage `json:"details"`
}

func (e Event) Validate() error {
	for name, value := range map[string]string{
		"id": e.ID, "tenant_id": e.TenantID, "sensor_id": e.SensorID,
		"host_id": e.HostID, "boot_id": e.BootID,
	} {
		if strings.TrimSpace(value) == "" || len(value) > 256 {
			return fmt.Errorf("%s is required and must be at most 256 characters", name)
		}
	}
	if e.SchemaVersion == 0 {
		return fmt.Errorf("schema_version must be positive")
	}
	if _, ok := knownEventKinds[e.Kind]; !ok {
		return fmt.Errorf("unknown event kind %q", e.Kind)
	}
	if e.Outcome != OutcomeSuccess && e.Outcome != OutcomeFailure &&
		e.Outcome != OutcomeAttempt && e.Outcome != OutcomeUnknown {
		return fmt.Errorf("unknown outcome %q", e.Outcome)
	}
	if e.ObservedAt.IsZero() || e.IngestedAt.IsZero() {
		return fmt.Errorf("observed_at and ingested_at are required")
	}
	if len(e.Details) > 64*1024 {
		return fmt.Errorf("details exceeds 64KiB")
	}
	if len(e.Details) > 0 && !json.Valid(e.Details) {
		return fmt.Errorf("details must be valid JSON")
	}
	return nil
}

type Scope struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	Start            time.Time `json:"start"`
	End              time.Time `json:"end"`
	AllowedHosts     []string  `json:"allowed_hosts"`
	AllowedWorkloads []string  `json:"allowed_workloads"`
	SnapshotID       string    `json:"snapshot_id"`
}

func (s Scope) Contains(e Event) bool {
	if e.TenantID != s.TenantID || e.ObservedAt.Before(s.Start) || e.ObservedAt.After(s.End) {
		return false
	}
	if len(s.AllowedHosts) > 0 {
		allowed := false
		for _, host := range s.AllowedHosts {
			if host == e.HostID {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}
	if len(s.AllowedWorkloads) > 0 {
		for _, workload := range s.AllowedWorkloads {
			if workload == e.ContainerID {
				return true
			}
		}
		return false
	}
	return true
}

type EntityType string

const (
	EntityAlert     EntityType = "ALERT"
	EntityIdentity  EntityType = "IDENTITY"
	EntitySession   EntityType = "SESSION"
	EntityHost      EntityType = "HOST"
	EntityWorkload  EntityType = "WORKLOAD"
	EntityContainer EntityType = "CONTAINER"
	EntityProcess   EntityType = "PROCESS"
	EntityFile      EntityType = "FILE"
	EntityIP        EntityType = "IP"
	EntityDomain    EntityType = "DOMAIN"
	EntityRequest   EntityType = "REQUEST"
	EntityCloud     EntityType = "CLOUD_RESOURCE"
)

type Entity struct {
	ID         string          `json:"id"`
	Type       EntityType      `json:"type"`
	TenantID   string          `json:"tenant_id"`
	ScopeID    string          `json:"scope_id"`
	SnapshotID string          `json:"snapshot_id"`
	Attributes json.RawMessage `json:"attributes,omitempty"`
}

type Alert struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	SeedEventID string    `json:"seed_event_id"`
	CreatedAt   time.Time `json:"created_at"`
}

type Evidence struct {
	ID            string          `json:"id"`
	RunID         string          `json:"run_id"`
	QueryID       string          `json:"query_id"`
	Source        string          `json:"source"`
	SourceEventID string          `json:"source_event_id"`
	ObservedAt    time.Time       `json:"observed_at"`
	SubjectRefs   []string        `json:"subject_refs"`
	ObjectRefs    []string        `json:"object_refs"`
	Fact          string          `json:"fact"`
	RawRef        string          `json:"raw_ref,omitempty"`
	SourceHash    string          `json:"source_hash"`
	Event         json.RawMessage `json:"event"`
}
