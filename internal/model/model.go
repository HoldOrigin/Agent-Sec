package model

import "time"

type RuntimeEvent struct {
	EventID               string         `json:"event_id"`
	Timestamp             time.Time      `json:"timestamp"`
	Type                  string         `json:"type"`
	EventType             string         `json:"event_type"`
	Host                  string         `json:"host"`
	HostID                string         `json:"host_id"`
	BootID                string         `json:"boot_id"`
	PID                   int            `json:"pid"`
	PPID                  int            `json:"ppid"`
	Process               string         `json:"process"`
	Exe                   string         `json:"exe"`
	Argv                  []string       `json:"argv"`
	Cmdline               string         `json:"cmdline"`
	ParentProcess         string         `json:"parent_process"`
	ProcessStartTime      string         `json:"process_start_time"`
	ProcessEntityID       string         `json:"process_entity_id"`
	ParentProcessEntityID string         `json:"parent_process_entity_id"`
	UID                   any            `json:"uid,omitempty"`
	ContainerID           string         `json:"container_id,omitempty"`
	PodUID                string         `json:"pod_uid,omitempty"`
	Pod                   string         `json:"pod,omitempty"`
	Workload              string         `json:"workload,omitempty"`
	Namespace             string         `json:"namespace,omitempty"`
	CgroupID              string         `json:"cgroup_id,omitempty"`
	Metadata              map[string]any `json:"metadata"`
}

type BehaviorDefinition struct {
	Type      string `json:"type"`
	RiskScore int    `json:"risk_score"`
}

type EntityRef struct {
	Type   string `json:"type"`
	ID     string `json:"id,omitempty"`
	Name   string `json:"name,omitempty"`
	Path   string `json:"path,omitempty"`
	Value  string `json:"value,omitempty"`
	Port   int    `json:"port,omitempty"`
	Hash   string `json:"hash,omitempty"`
	Source string `json:"source,omitempty"`
}

type Scope struct {
	HostID      string `json:"host_id"`
	ContainerID string `json:"container_id,omitempty"`
	Workload    string `json:"workload,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
}

type Behavior struct {
	BehaviorID     string         `json:"behavior_id"`
	Code           string         `json:"code"`
	Type           string         `json:"type"`
	Timestamp      time.Time      `json:"timestamp"`
	Subject        EntityRef      `json:"subject"`
	Object         EntityRef      `json:"object"`
	RiskScore      int            `json:"risk_score"`
	Evidence       []string       `json:"evidence"`
	Scope          Scope          `json:"scope"`
	ProcessTreeID  string         `json:"process_tree_id"`
	CorrelationKey string         `json:"correlation_key"`
	Details        map[string]any `json:"details"`
}

type Alert struct {
	AlertID        string    `json:"alert_id"`
	Title          string    `json:"title"`
	Severity       string    `json:"severity"`
	RuleIDs        []string  `json:"rule_ids"`
	EventIDs       []string  `json:"event_ids"`
	EventID        string    `json:"event_id"`
	CorrelationKey string    `json:"correlation_key"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type GraphNode struct {
	ID       string         `json:"id"`
	Type     string         `json:"type"`
	Label    string         `json:"label"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type GraphEdge struct {
	Source          string `json:"source"`
	Target          string `json:"target"`
	Relation        string `json:"relation"`
	EvidenceEventID string `json:"evidence_event_id"`
}

type Graph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

type RootCause struct {
	Entity     string   `json:"entity"`
	Assessment string   `json:"assessment"`
	Observed   string   `json:"observed"`
	Inferred   string   `json:"inferred"`
	Evidence   []string `json:"evidence"`
}

type Finding struct {
	Claim      string   `json:"claim"`
	Evidence   []string `json:"evidence"`
	Limitation string   `json:"limitation,omitempty"`
}

type AttackStoryStep struct {
	Step     int      `json:"step"`
	Behavior string   `json:"behavior"`
	Entity   string   `json:"entity"`
	Observed bool     `json:"observed"`
	Evidence []string `json:"evidence"`
}

type Evidence struct {
	EventID           string    `json:"event_id"`
	Timestamp         time.Time `json:"timestamp"`
	Type              string    `json:"type"`
	ProcessEntityID   string    `json:"process_entity_id"`
	Fact              string    `json:"fact"`
	SupportsBehaviors []string  `json:"supports_behaviors"`
}

type TimelineEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	EventID     string    `json:"event_id"`
	Description string    `json:"description"`
}

type PolicyDecision struct {
	Decision      string    `json:"decision"`
	Allow         bool      `json:"allow"`
	Approval      bool      `json:"approval"`
	Reason        string    `json:"reason"`
	PolicyVersion string    `json:"policy_version"`
	EvaluatedAt   time.Time `json:"evaluated_at"`
}

type Recommendation struct {
	Action    string         `json:"action"`
	Title     string         `json:"title"`
	Target    map[string]any `json:"target"`
	Rationale string         `json:"rationale"`
	Policy    PolicyDecision `json:"policy"`
}

type ToolTrace struct {
	Step        int    `json:"step"`
	Tool        string `json:"tool"`
	Purpose     string `json:"purpose"`
	ResultCount int    `json:"result_count"`
}

type BlastRadius struct {
	ContainerCount       int      `json:"container_count"`
	Assessment           string   `json:"assessment"`
	AffectedContainerIDs []string `json:"affected_container_ids"`
	SameHashMatches      []string `json:"same_hash_matches"`
	SameIPMatches        []string `json:"same_ip_matches"`
}

type InvestigationStats struct {
	ToolCalls           int      `json:"tool_calls"`
	ContextTypes        []string `json:"context_types"`
	ProcessNodes        int      `json:"process_nodes"`
	CompressedInput     bool     `json:"compressed_input"`
	RawSyscallsSentToAI int      `json:"raw_syscalls_sent_to_ai"`
	ProcessEventCount   int      `json:"process_event_count"`
}

type Incident struct {
	IncidentID         string             `json:"incident_id"`
	AlertID            string             `json:"alert_id,omitempty"`
	Type               string             `json:"type"`
	Title              string             `json:"title"`
	Severity           string             `json:"severity"`
	Risk               string             `json:"risk"`
	RiskScore          int                `json:"risk_score"`
	Score              int                `json:"score"`
	Verdict            string             `json:"verdict"`
	Classification     string             `json:"classification"`
	Confidence         float64            `json:"confidence"`
	Summary            string             `json:"summary"`
	Workload           string             `json:"workload"`
	Namespace          string             `json:"namespace"`
	ContainerID        string             `json:"container_id"`
	HostID             string             `json:"host_id"`
	StartTime          time.Time          `json:"start_time"`
	EndTime            time.Time          `json:"end_time"`
	RootProcess        string             `json:"root_process"`
	RootProcessName    string             `json:"root_process_name"`
	BehaviorIDs        []string           `json:"behavior_ids"`
	BehaviorTypes      []string           `json:"behavior_types"`
	Behaviors          []Behavior         `json:"behaviors"`
	EvidenceEventIDs   []string           `json:"evidence_event_ids"`
	Correlation        map[string]any     `json:"correlation"`
	RootCause          RootCause          `json:"root_cause"`
	ObservedFindings   []Finding          `json:"observed_findings"`
	InferredFindings   []Finding          `json:"inferred_findings"`
	AttackStory        []AttackStoryStep  `json:"attack_story"`
	Graph              Graph              `json:"graph"`
	Timeline           []TimelineEntry    `json:"timeline"`
	AffectedAssets     []map[string]any   `json:"affected_assets"`
	BlastRadius        BlastRadius        `json:"blast_radius"`
	Entities           []string           `json:"entities"`
	Evidence           []Evidence         `json:"evidence"`
	Recommendations    []Recommendation   `json:"recommendations"`
	ToolTrace          []ToolTrace        `json:"tool_trace"`
	InvestigationStats InvestigationStats `json:"investigation_stats"`
	Status             string             `json:"status"`
	CreatedAt          time.Time          `json:"created_at"`
	UpdatedAt          time.Time          `json:"updated_at"`
}

type ProcessorStats struct {
	Received     int `json:"received"`
	Accepted     int `json:"accepted"`
	Deduplicated int `json:"deduplicated"`
	Filtered     int `json:"filtered"`
	Promoted     int `json:"promoted"`
}

type ProcessResult struct {
	Accepted         []RuntimeEvent `json:"accepted"`
	Dropped          string         `json:"dropped,omitempty"`
	PromotedEventIDs []string       `json:"promoted_event_ids"`
}

type CollectionPolicy struct {
	Scope     Scope      `json:"scope"`
	Level     string     `json:"level"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}
