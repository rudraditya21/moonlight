use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::thread;

use corelib::campaign::{
    validate_prerequisite_graph, Campaign, CampaignEventPayload, CampaignId, CampaignStatus,
    FindingSnapshot, MetadataValue, Objective, ObjectiveEvaluationEngine, ObjectiveId,
    ObjectiveIngestionDispatcher, ObjectiveIngestionEvent, ObjectiveReevaluationTrigger,
    ObjectiveStatus, Predicate, PredicateSnapshot, RiskLevel, RunSnapshot, SessionPrivilegeLevel,
    SessionSnapshot,
};
use corelib::control::ControlState;
use corelib::domain::{
    Artifact, ArtifactKind, Finding, FindingSeverity, ModuleVersion, Run, RunState, Session,
    SessionState, Task, TaskState, Workspace,
};
use corelib::orchestrator::{
    DispatchOutcome, InMemoryAuditLogStore, InMemorySnapshotStore, ObservableExecutionOrchestrator,
    OrchestratorError, PlannedTask, RunPlan, RunRequest, StaticRunPlanner, TaskExecutionContext,
    TaskExecutionOutcome, TaskExecutionReport, TaskExecutor,
};

#[derive(Clone, Copy)]
struct Lcg {
    state: u64,
}

impl Lcg {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.state
    }

    fn next_bool(&mut self) -> bool {
        (self.next_u64() & 1) == 1
    }

    fn choose<T: Copy>(&mut self, values: &[T]) -> T {
        values[(self.next_u64() as usize) % values.len()]
    }
}

#[derive(Clone, Copy)]
struct SnapshotFlags {
    finding_shell: bool,
    finding_post: bool,
    artifact_loot: bool,
    session_root: bool,
    run_success: bool,
    owner_red: bool,
    fail_flag: bool,
}

fn deterministic_uuid(seed: u128) -> String {
    let hex = format!("{seed:032x}");
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn deterministic_campaign_id(seed: u128) -> CampaignId {
    CampaignId::parse(&deterministic_uuid(seed)).expect("campaign id")
}

fn deterministic_objective_id(seed: u128) -> ObjectiveId {
    ObjectiveId::parse(&deterministic_uuid(seed)).expect("objective id")
}

fn build_snapshot(flags: SnapshotFlags) -> PredicateSnapshot {
    let workspace = Workspace::new_at("ws", "advanced-matrix", 1).expect("workspace");
    let module = ModuleVersion::new_at(
        "exploit/linux/example",
        "1.0.0",
        1,
        "builtin://example",
        "0123456789abcdef",
        1,
    )
    .expect("module");
    let mut run = Run::new_at(workspace.id, module.id, None, "operator", 2).expect("run");
    if flags.run_success {
        run.transition_state(RunState::Running, 3)
            .expect("run->running");
        run.transition_state(RunState::Succeeded, 4)
            .expect("run->succeeded");
    }
    let session = Session::new_at(run.id, None, "shell", "127.0.0.1:23", 5).expect("session");
    let artifact = Artifact::new_at(
        run.id,
        None,
        Some(session.id),
        ArtifactKind::CommandOutput,
        "stdout",
        "mem://stdout",
        6,
    )
    .expect("artifact");
    let finding = Finding::new_at(
        run.id,
        None,
        Some(session.id),
        "shell found",
        "deterministic test finding",
        FindingSeverity::High,
        7,
    )
    .expect("finding");
    let post_finding = Finding::new_at(
        run.id,
        None,
        Some(session.id),
        "post objective",
        "deterministic post finding",
        FindingSeverity::Medium,
        8,
    )
    .expect("post finding");

    let mut snapshot = PredicateSnapshot::new().with_run(
        RunSnapshot::new(run, "exploit/linux/example")
            .expect("run snapshot")
            .with_metadata(
                "owner",
                if flags.owner_red {
                    MetadataValue::Text("red".to_string())
                } else {
                    MetadataValue::Text("blue".to_string())
                },
            ),
    );

    let mut artifact_snapshot = corelib::campaign::ArtifactSnapshot::new(artifact);
    if flags.artifact_loot {
        artifact_snapshot = artifact_snapshot.with_tag("loot");
    }
    snapshot = snapshot.with_artifact(artifact_snapshot);

    let finding_type = if flags.finding_shell {
        "shell_access"
    } else {
        "other_access"
    };
    snapshot = snapshot.with_finding(
        FindingSnapshot::new(finding, finding_type)
            .expect("finding snapshot")
            .with_metadata(
                "stage",
                if flags.finding_shell {
                    MetadataValue::Integer(1)
                } else {
                    MetadataValue::Integer(0)
                },
            ),
    );
    if flags.finding_post {
        snapshot = snapshot.with_finding(
            FindingSnapshot::new(post_finding, "post_access").expect("post finding snapshot"),
        );
    }

    let mut session_snapshot = SessionSnapshot::new(session);
    if flags.session_root {
        session_snapshot = session_snapshot.with_privilege(SessionPrivilegeLevel::Root);
    } else {
        session_snapshot = session_snapshot.with_privilege(SessionPrivilegeLevel::User);
    }
    snapshot = snapshot.with_session(session_snapshot);

    snapshot
        .with_metadata(
            "owner",
            if flags.owner_red {
                MetadataValue::Text("red".to_string())
            } else {
                MetadataValue::Text("blue".to_string())
            },
        )
        .with_metadata("fail", MetadataValue::Bool(flags.fail_flag))
}

fn build_objective(
    objective_id: ObjectiveId,
    campaign_id: CampaignId,
    name: &str,
    prerequisites: Vec<ObjectiveId>,
    success_criteria: Vec<Predicate>,
    failure_criteria: Vec<Predicate>,
    risk_level: RiskLevel,
    now: u64,
) -> Objective {
    Objective::new_at(
        objective_id,
        campaign_id,
        name,
        "",
        prerequisites,
        success_criteria,
        failure_criteria,
        risk_level,
        None,
        now,
    )
    .expect("objective")
}

#[derive(Default)]
struct AlwaysSuccessExecutor;

impl TaskExecutor for AlwaysSuccessExecutor {
    fn execute(
        &mut self,
        context: &TaskExecutionContext,
    ) -> Result<TaskExecutionReport, OrchestratorError> {
        Ok(TaskExecutionReport {
            elapsed_ms: 1,
            outcome: TaskExecutionOutcome::Success {
                message: format!("ok:{}", context.task_name),
            },
        })
    }
}

#[test]
fn state_machine_legality_holds_under_randomized_sequences() {
    let mut rng = Lcg::new(0xC0FFEE);
    const RUN_STATES: [RunState; 5] = [
        RunState::Queued,
        RunState::Running,
        RunState::Succeeded,
        RunState::Failed,
        RunState::Canceled,
    ];
    const TASK_STATES: [TaskState; 6] = [
        TaskState::Queued,
        TaskState::Running,
        TaskState::Retrying,
        TaskState::Succeeded,
        TaskState::Failed,
        TaskState::Canceled,
    ];
    const SESSION_STATES: [SessionState; 5] = [
        SessionState::Opening,
        SessionState::Open,
        SessionState::Backgrounded,
        SessionState::Lost,
        SessionState::Closed,
    ];
    const CAMPAIGN_STATES: [CampaignStatus; 4] = [
        CampaignStatus::Active,
        CampaignStatus::Paused,
        CampaignStatus::Completed,
        CampaignStatus::Failed,
    ];

    for case in 0..64u64 {
        let mut campaign = Campaign::new_at(
            deterministic_campaign_id(10_000 + case as u128),
            "op",
            "",
            1,
            None,
        )
        .expect("campaign");
        let workspace = Workspace::new_at("ws", "test", 1).expect("workspace");
        let module =
            ModuleVersion::new_at("module", "1.0.0", 1, "entry", "digest", 1).expect("module");
        let mut run = Run::new_at(workspace.id, module.id, None, "operator", 1).expect("run");
        let mut task = Task::new_at(run.id, "stage", 1024, 1).expect("task");
        let mut session =
            Session::new_at(run.id, Some(task.id), "shell", "127.0.0.1", 1).expect("session");

        for step in 0..64u64 {
            let next_campaign = rng.choose(&CAMPAIGN_STATES);
            let campaign_expected = campaign.status.can_transition_to(next_campaign);
            let campaign_ok = campaign.transition_status(next_campaign).is_ok();
            assert_eq!(
                campaign_ok, campaign_expected,
                "campaign transition mismatch"
            );

            let next_run = rng.choose(&RUN_STATES);
            let run_expected = run.state.can_transition_to(next_run);
            let run_ok = run.transition_state(next_run, 2 + step).is_ok();
            assert_eq!(run_ok, run_expected, "run transition mismatch");

            let next_task = rng.choose(&TASK_STATES);
            let task_expected = task.state.can_transition_to(next_task);
            let task_ok = task.transition_state(next_task, 2 + step).is_ok();
            assert_eq!(task_ok, task_expected, "task transition mismatch");

            let next_session = rng.choose(&SESSION_STATES);
            let session_expected = session.state.can_transition_to(next_session);
            let session_ok = session.transition_state(next_session, 2 + step).is_ok();
            assert_eq!(session_ok, session_expected, "session transition mismatch");
        }
    }
}

#[test]
fn predicate_determinism_holds_for_randomized_snapshots() {
    let mut rng = Lcg::new(0xABCD1234);
    let predicates = vec![
        Predicate::FindingExists {
            finding_type: "shell_access".to_string(),
        },
        Predicate::SessionPrivilege {
            level: SessionPrivilegeLevel::Root,
        },
        Predicate::ArtifactTagMatch {
            tag: "loot".to_string(),
        },
        Predicate::RunSucceeded {
            module_name: "exploit/linux/example".to_string(),
        },
        Predicate::CustomMetadataMatch {
            key: "owner".to_string(),
            value: MetadataValue::Text("red".to_string()),
        },
    ];

    for _ in 0..128 {
        let flags = SnapshotFlags {
            finding_shell: rng.next_bool(),
            finding_post: rng.next_bool(),
            artifact_loot: rng.next_bool(),
            session_root: rng.next_bool(),
            run_success: rng.next_bool(),
            owner_red: rng.next_bool(),
            fail_flag: rng.next_bool(),
        };
        let snapshot = build_snapshot(flags);
        let mut reversed = snapshot.clone();
        reversed.artifacts.reverse();
        reversed.findings.reverse();
        reversed.sessions.reverse();
        reversed.runs.reverse();

        for predicate in &predicates {
            let baseline = predicate.evaluate_snapshot(&snapshot);
            for _ in 0..8 {
                assert_eq!(baseline, predicate.evaluate_snapshot(&snapshot));
            }
            assert_eq!(baseline, predicate.evaluate_snapshot(&reversed));

            let wire = predicate.to_wire_bytes();
            let decoded = Predicate::from_wire_bytes(&wire).expect("predicate wire round trip");
            assert_eq!(baseline, decoded.evaluate_snapshot(&snapshot));
        }
    }
}

#[test]
fn replay_golden_trace_matches_expected_campaign_projection() {
    let mut orchestrator = ObservableExecutionOrchestrator::new(
        InMemorySnapshotStore::default(),
        InMemoryAuditLogStore::default(),
    )
    .expect("orchestrator");

    let campaign_id = deterministic_campaign_id(20_001);
    let objective_a = deterministic_objective_id(20_101);
    let objective_b = deterministic_objective_id(20_102);

    let payloads = vec![
        CampaignEventPayload::CampaignCreated {
            campaign_id: campaign_id.clone(),
            name: "golden".to_string(),
        },
        CampaignEventPayload::ObjectiveCreated {
            campaign_id: campaign_id.clone(),
            objective_id: objective_a.clone(),
            name: "foothold".to_string(),
            risk_level: RiskLevel::High,
        },
        CampaignEventPayload::ObjectiveCreated {
            campaign_id: campaign_id.clone(),
            objective_id: objective_b.clone(),
            name: "post".to_string(),
            risk_level: RiskLevel::Medium,
        },
        CampaignEventPayload::ObjectivePrereqLinked {
            campaign_id: campaign_id.clone(),
            objective_id: objective_b.clone(),
            prerequisite_id: objective_a.clone(),
        },
        CampaignEventPayload::ObjectiveStatusChanged {
            campaign_id: campaign_id.clone(),
            objective_id: objective_a.clone(),
            from: ObjectiveStatus::Pending,
            to: ObjectiveStatus::Eligible,
            reason: Some("prereq met".to_string()),
        },
        CampaignEventPayload::ObjectiveStatusChanged {
            campaign_id: campaign_id.clone(),
            objective_id: objective_a.clone(),
            from: ObjectiveStatus::Eligible,
            to: ObjectiveStatus::InProgress,
            reason: Some("operator start".to_string()),
        },
        CampaignEventPayload::ObjectiveStatusChanged {
            campaign_id: campaign_id.clone(),
            objective_id: objective_a.clone(),
            from: ObjectiveStatus::InProgress,
            to: ObjectiveStatus::Achieved,
            reason: Some("criteria met".to_string()),
        },
        CampaignEventPayload::ObjectiveStatusChanged {
            campaign_id: campaign_id.clone(),
            objective_id: objective_b.clone(),
            from: ObjectiveStatus::Pending,
            to: ObjectiveStatus::Eligible,
            reason: Some("depends achieved".to_string()),
        },
        CampaignEventPayload::ObjectiveEvaluated {
            campaign_id: campaign_id.clone(),
            objective_id: objective_a.clone(),
            trigger: ObjectiveReevaluationTrigger::ManualRequest,
            prerequisites_satisfied: true,
            success_criteria_satisfied: true,
            failure_criteria_satisfied: false,
            resulting_status: ObjectiveStatus::Achieved,
        },
        CampaignEventPayload::ObjectiveEvaluated {
            campaign_id: campaign_id.clone(),
            objective_id: objective_b.clone(),
            trigger: ObjectiveReevaluationTrigger::ManualRequest,
            prerequisites_satisfied: true,
            success_criteria_satisfied: false,
            failure_criteria_satisfied: false,
            resulting_status: ObjectiveStatus::Eligible,
        },
    ];

    orchestrator
        .record_campaign_events(payloads.clone(), None)
        .expect("record campaign events");

    let report = orchestrator
        .reconstruct_campaign_from_history(&campaign_id)
        .expect("reconstruct");
    assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
    let campaign = report.campaign.expect("campaign");
    assert_eq!(campaign.sequence_high_watermark, payloads.len() as u64);
    assert_eq!(campaign.objective_ids.len(), 2);
    assert_eq!(
        campaign.objectives.get(&objective_a).expect("a").status,
        ObjectiveStatus::Achieved
    );
    assert_eq!(
        campaign.objectives.get(&objective_b).expect("b").status,
        ObjectiveStatus::Eligible
    );

    let mut snapshot = ControlState::default();
    let mut campaign_state =
        Campaign::new_at(campaign_id.clone(), "golden", "", 1, None).expect("campaign");
    campaign_state.add_objective(objective_a.clone());
    campaign_state.add_objective(objective_b.clone());

    let mut objective_state_a = build_objective(
        objective_a.clone(),
        campaign_id.clone(),
        "foothold",
        vec![],
        vec![Predicate::FindingExists {
            finding_type: "shell_access".to_string(),
        }],
        vec![],
        RiskLevel::High,
        1,
    );
    objective_state_a.status = ObjectiveStatus::Achieved;

    let mut objective_state_b = build_objective(
        objective_b.clone(),
        campaign_id.clone(),
        "post",
        vec![objective_a.clone()],
        vec![Predicate::FindingExists {
            finding_type: "post_access".to_string(),
        }],
        vec![],
        RiskLevel::Medium,
        1,
    );
    objective_state_b.status = ObjectiveStatus::Eligible;

    snapshot
        .campaigns
        .insert(campaign_id.clone(), campaign_state);
    snapshot
        .objectives
        .insert(objective_a.clone(), objective_state_a);
    snapshot
        .objectives
        .insert(objective_b.clone(), objective_state_b);

    let consistency = orchestrator
        .replay_campaign_consistency(&campaign_id, &snapshot)
        .expect("consistency");
    assert!(
        consistency.consistent,
        "{:?}",
        consistency.report.diagnostics
    );
}

#[test]
fn restart_safety_preserves_orchestrator_progress_and_replay_state() {
    let snapshot_shared = Arc::new(Mutex::new(None));
    let audit_shared = Arc::new(Mutex::new(Vec::new()));

    let workspace = Workspace::new_at("ws", "restart", 1).expect("workspace");
    let module =
        ModuleVersion::new_at("mod", "1.0.0", 1, "builtin://mod", "abc123", 1).expect("module");
    let request = RunRequest::new(workspace.id, module.id, None, "operator").expect("request");
    let plan = RunPlan::new(vec![
        PlannedTask::new("stage-1", 3, 1000, "idem-stage-1").expect("task-1"),
        PlannedTask::new("stage-2", 3, 1000, "idem-stage-2").expect("task-2"),
    ])
    .expect("plan");
    let planner = StaticRunPlanner::new(plan);

    let run_id = {
        let mut orchestrator = ObservableExecutionOrchestrator::new(
            InMemorySnapshotStore::from_shared(Arc::clone(&snapshot_shared)),
            InMemoryAuditLogStore::from_shared(Arc::clone(&audit_shared)),
        )
        .expect("orchestrator");
        let run_id = orchestrator
            .submit_with_planner(request.clone(), &planner)
            .expect("submit");
        let mut executor = AlwaysSuccessExecutor;
        let first = orchestrator.dispatch_next(&mut executor).expect("dispatch");
        assert!(matches!(first, DispatchOutcome::Succeeded { .. }));
        assert_eq!(orchestrator.pending_tasks(), 1);
        run_id
    };

    let mut recovered = ObservableExecutionOrchestrator::new(
        InMemorySnapshotStore::from_shared(Arc::clone(&snapshot_shared)),
        InMemoryAuditLogStore::from_shared(Arc::clone(&audit_shared)),
    )
    .expect("recovered orchestrator");
    assert_eq!(recovered.pending_tasks(), 1);
    assert_eq!(recovered.run_state(run_id), Some(RunState::Running));

    let mut executor = AlwaysSuccessExecutor;
    while recovered.pending_tasks() > 0 {
        let _ = recovered.dispatch_next(&mut executor).expect("dispatch");
    }
    assert_eq!(recovered.run_state(run_id), Some(RunState::Succeeded));

    let replayed = recovered
        .reconstruct_run_from_history(run_id)
        .expect("replayed")
        .expect("run");
    assert_eq!(replayed.state, RunState::Succeeded);
    assert!(replayed
        .tasks
        .values()
        .all(|task| task.state == TaskState::Succeeded));
}

#[test]
fn ingestion_dedup_is_idempotent_for_repeated_event_keys() {
    let campaign_id = deterministic_campaign_id(30_001);
    let objective_id = deterministic_objective_id(30_101);

    let objective = build_objective(
        objective_id.clone(),
        campaign_id.clone(),
        "idempotent-objective",
        vec![],
        vec![Predicate::FindingExists {
            finding_type: "shell_access".to_string(),
        }],
        vec![],
        RiskLevel::Low,
        1,
    );
    let mut objectives = BTreeMap::from([(objective_id.clone(), objective)]);
    let snapshot = build_snapshot(SnapshotFlags {
        finding_shell: true,
        finding_post: false,
        artifact_loot: false,
        session_root: false,
        run_success: false,
        owner_red: false,
        fail_flag: false,
    });
    let event = ObjectiveIngestionEvent::new(
        campaign_id.clone(),
        ObjectiveReevaluationTrigger::FindingCreated,
        "finding:1",
    )
    .expect("event");

    let mut dispatcher = ObjectiveIngestionDispatcher::default();
    let first = dispatcher
        .dispatch(&event, &mut objectives, &snapshot, 10)
        .expect("first");
    let second = dispatcher
        .dispatch(&event, &mut objectives, &snapshot, 11)
        .expect("second");

    assert!(!first.skipped_duplicate);
    assert!(second.skipped_duplicate);
    assert!(second.records.is_empty());
    assert!(second.emitted_events.is_empty());
    assert_eq!(
        objectives.get(&objective_id).expect("objective").status,
        ObjectiveStatus::Eligible
    );
}

#[test]
fn concurrent_ingestion_race_keeps_single_non_duplicate_dispatch() {
    let campaign_id = deterministic_campaign_id(31_001);
    let objective_id = deterministic_objective_id(31_101);
    let objective = build_objective(
        objective_id.clone(),
        campaign_id.clone(),
        "race-objective",
        vec![],
        vec![Predicate::FindingExists {
            finding_type: "shell_access".to_string(),
        }],
        vec![],
        RiskLevel::Low,
        1,
    );

    let dispatcher = Arc::new(Mutex::new(ObjectiveIngestionDispatcher::default()));
    let objectives = Arc::new(Mutex::new(BTreeMap::from([(
        objective_id.clone(),
        objective,
    )])));
    let snapshot = Arc::new(build_snapshot(SnapshotFlags {
        finding_shell: true,
        finding_post: false,
        artifact_loot: false,
        session_root: false,
        run_success: false,
        owner_red: false,
        fail_flag: false,
    }));
    let event = Arc::new(
        ObjectiveIngestionEvent::new(
            campaign_id.clone(),
            ObjectiveReevaluationTrigger::FindingCreated,
            "finding:race",
        )
        .expect("event"),
    );

    let mut handles = Vec::new();
    for thread_idx in 0..24u64 {
        let dispatcher = Arc::clone(&dispatcher);
        let objectives = Arc::clone(&objectives);
        let snapshot = Arc::clone(&snapshot);
        let event = Arc::clone(&event);
        handles.push(thread::spawn(move || {
            let mut dispatcher_guard = dispatcher.lock().expect("dispatcher lock");
            let mut objective_guard = objectives.lock().expect("objectives lock");
            dispatcher_guard
                .dispatch(&event, &mut objective_guard, &snapshot, 100 + thread_idx)
                .expect("dispatch")
                .skipped_duplicate
        }));
    }

    let skipped = handles
        .into_iter()
        .map(|handle| handle.join().expect("join"))
        .collect::<Vec<_>>();
    let non_duplicate_count = skipped.iter().filter(|value| !**value).count();
    assert_eq!(non_duplicate_count, 1);

    let objectives_guard = objectives.lock().expect("objectives lock");
    assert_eq!(
        objectives_guard
            .get(&objective_id)
            .expect("objective")
            .status,
        ObjectiveStatus::Eligible
    );
}

#[test]
fn randomized_transition_fuzz_preserves_replay_equivalence() {
    let mut rng = Lcg::new(0xBADC0DE);

    for case in 0..48u128 {
        let campaign_id = deterministic_campaign_id(40_000 + case);
        let objective_a = deterministic_objective_id(41_000 + (case * 2));
        let objective_b = deterministic_objective_id(41_001 + (case * 2));

        let flags = SnapshotFlags {
            finding_shell: rng.next_bool(),
            finding_post: rng.next_bool(),
            artifact_loot: rng.next_bool(),
            session_root: rng.next_bool(),
            run_success: rng.next_bool(),
            owner_red: rng.next_bool(),
            fail_flag: rng.next_bool(),
        };
        let snapshot = build_snapshot(flags);

        let mut objectives = BTreeMap::new();
        let objective_state_a = build_objective(
            objective_a.clone(),
            campaign_id.clone(),
            "phase-a",
            vec![],
            vec![Predicate::FindingExists {
                finding_type: "shell_access".to_string(),
            }],
            vec![Predicate::CustomMetadataMatch {
                key: "fail".to_string(),
                value: MetadataValue::Bool(true),
            }],
            RiskLevel::High,
            1,
        );
        let objective_state_b = build_objective(
            objective_b.clone(),
            campaign_id.clone(),
            "phase-b",
            vec![objective_a.clone()],
            vec![Predicate::FindingExists {
                finding_type: "post_access".to_string(),
            }],
            vec![Predicate::CustomMetadataMatch {
                key: "fail".to_string(),
                value: MetadataValue::Bool(true),
            }],
            RiskLevel::Medium,
            1,
        );
        objectives.insert(objective_a.clone(), objective_state_a);
        objectives.insert(objective_b.clone(), objective_state_b);
        validate_prerequisite_graph(&objectives.values().cloned().collect::<Vec<_>>())
            .expect("graph valid");

        let mut emitted = Vec::<CampaignEventPayload>::new();
        let _ = ObjectiveEvaluationEngine::evaluate_campaign(
            &campaign_id,
            &mut objectives,
            &snapshot,
            ObjectiveReevaluationTrigger::ManualRequest,
            10,
            &mut emitted,
        )
        .expect("initial evaluation");

        let status_index = objectives
            .iter()
            .map(|(id, objective)| (id.clone(), objective.status))
            .collect::<BTreeMap<_, _>>();
        if objectives
            .get(&objective_a)
            .is_some_and(|objective| objective.status == ObjectiveStatus::Eligible)
        {
            ObjectiveEvaluationEngine::start_objective(
                objectives.get_mut(&objective_a).expect("objective a"),
                &status_index,
                11,
                &mut emitted,
            )
            .expect("start a");
        }

        let _ = ObjectiveEvaluationEngine::evaluate_campaign(
            &campaign_id,
            &mut objectives,
            &snapshot,
            ObjectiveReevaluationTrigger::ManualRequest,
            12,
            &mut emitted,
        )
        .expect("second evaluation");

        let status_index = objectives
            .iter()
            .map(|(id, objective)| (id.clone(), objective.status))
            .collect::<BTreeMap<_, _>>();
        if objectives
            .get(&objective_b)
            .is_some_and(|objective| objective.status == ObjectiveStatus::Eligible)
        {
            ObjectiveEvaluationEngine::start_objective(
                objectives.get_mut(&objective_b).expect("objective b"),
                &status_index,
                13,
                &mut emitted,
            )
            .expect("start b");
        }

        let _ = ObjectiveEvaluationEngine::evaluate_campaign(
            &campaign_id,
            &mut objectives,
            &snapshot,
            ObjectiveReevaluationTrigger::ManualRequest,
            14,
            &mut emitted,
        )
        .expect("final evaluation");

        let mut orchestrator = ObservableExecutionOrchestrator::new(
            InMemorySnapshotStore::default(),
            InMemoryAuditLogStore::default(),
        )
        .expect("orchestrator");
        let mut payloads = vec![
            CampaignEventPayload::CampaignCreated {
                campaign_id: campaign_id.clone(),
                name: format!("fuzz-{case}"),
            },
            CampaignEventPayload::ObjectiveCreated {
                campaign_id: campaign_id.clone(),
                objective_id: objective_a.clone(),
                name: "phase-a".to_string(),
                risk_level: RiskLevel::High,
            },
            CampaignEventPayload::ObjectiveCreated {
                campaign_id: campaign_id.clone(),
                objective_id: objective_b.clone(),
                name: "phase-b".to_string(),
                risk_level: RiskLevel::Medium,
            },
            CampaignEventPayload::ObjectivePrereqLinked {
                campaign_id: campaign_id.clone(),
                objective_id: objective_b.clone(),
                prerequisite_id: objective_a.clone(),
            },
        ];
        payloads.extend(emitted.clone());
        orchestrator
            .record_campaign_events(payloads, None)
            .expect("record fuzz events");

        let report = orchestrator
            .reconstruct_campaign_from_history(&campaign_id)
            .expect("reconstruct");
        assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
        let replayed = report.campaign.expect("campaign");

        assert_eq!(
            replayed.objectives.get(&objective_a).expect("a").status,
            objectives.get(&objective_a).expect("a").status
        );
        assert_eq!(
            replayed.objectives.get(&objective_b).expect("b").status,
            objectives.get(&objective_b).expect("b").status
        );
    }
}
