use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use corelib::campaign::{CampaignId, ObjectiveId, ObjectiveStatus, Predicate, RiskLevel};
use corelib::planning::{
    execute_planner_pipeline, reconstruct_planning_from_events, AStarCostWeights,
    ConcurrentPlannerEngine, InMemoryPlannerStateStore, NormalizedPlannerSnapshot,
    ObjectiveDefinitionInput, PlanLifecycleStatus, PlanRequest, PlanRequestMode,
    PlannerEngineContext, PlannerNormalizationInput, PlannerStateManager, RegisteredModuleInput,
};

fn make_snapshot(module_count: usize) -> (NormalizedPlannerSnapshot, ObjectiveId) {
    let campaign_id = CampaignId::parse("c001c001-1111-2222-3333-444444444444").expect("campaign");
    let objective_id =
        ObjectiveId::parse("f001f001-1111-2222-3333-444444444444").expect("objective");
    let mut modules = Vec::with_capacity(module_count);
    for idx in 0..module_count {
        modules.push(
            RegisteredModuleInput::new(
                &format!("auxiliary/integration/{idx}"),
                if idx % 3 == 0 {
                    BTreeSet::from(["exploit_execution".to_string()])
                } else {
                    BTreeSet::new()
                },
                (idx % 10 + 1) as u32,
                if idx % 9 == 0 {
                    RiskLevel::High
                } else if idx % 3 == 0 {
                    RiskLevel::Medium
                } else {
                    RiskLevel::Low
                },
                7_000 + (idx as u16 % 1_000),
                BTreeSet::from([format!("artifact_type_{}", idx % 32)]),
                BTreeMap::new(),
            )
            .expect("module"),
        );
    }

    let objective = ObjectiveDefinitionInput::new(
        objective_id.clone(),
        campaign_id,
        ObjectiveStatus::Pending,
        vec![],
        vec![Predicate::RunSucceeded {
            module_name: format!("auxiliary/integration/{}", module_count - 1),
        }],
        vec![],
        RiskLevel::Low,
        None,
        BTreeMap::new(),
    )
    .expect("objective");

    let snapshot =
        PlannerNormalizationInput::new(modules, vec![objective], vec![], BTreeMap::new())
            .and_then(corelib::planning::normalize_planner_input)
            .expect("snapshot");
    (snapshot, objective_id)
}

fn result_fingerprint(result: &corelib::planning::PlanResult) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        result.objective_id.as_str(),
        result.status.as_str(),
        result.step_count,
        result.total_noise_cost,
        result
            .steps
            .iter()
            .map(|step| step.edge_id.as_str().to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}

#[test]
fn planning_integration_cold_recovery_is_equivalent_after_restart() {
    let (snapshot, objective_id) = make_snapshot(256);
    let request = PlanRequest::new(
        objective_id.clone(),
        PlanRequestMode::Plan,
        "integration.recover",
        None,
        false,
    )
    .expect("request");
    let context = PlannerEngineContext::new(42_000, BTreeSet::new(), AStarCostWeights::default());
    let output = execute_planner_pipeline(&snapshot, &request, &context).expect("plan output");
    assert_ne!(output.result.status, PlanLifecycleStatus::Failed);

    let mut manager =
        PlannerStateManager::new(InMemoryPlannerStateStore::default()).expect("manager");
    manager
        .record_execution(&snapshot, &request, &context, &output, 42_000)
        .expect("persist");
    let store = manager.into_store();
    let recovered = PlannerStateManager::new(store).expect("recovered manager");
    let report = recovered.cold_recover().expect("cold recover");

    assert!(report.consistent);
    assert_eq!(report.equivalence.len(), 1);
    assert!(report.equivalence[0].equivalent);

    let replay =
        reconstruct_planning_from_events(&recovered.state().event_log.events, &objective_id);
    assert!(replay.diagnostics.is_empty());
    assert!(replay.decision.is_some());
}

#[test]
fn planning_integration_supports_sustained_concurrent_requests() {
    let (snapshot, objective_id) = make_snapshot(1_024);
    let engine = Arc::new(ConcurrentPlannerEngine::new(&snapshot).expect("engine"));
    let workers = 6usize;
    let requests_per_worker = 48usize;
    let mut handles = Vec::with_capacity(workers);

    for worker in 0..workers {
        let engine = engine.clone();
        let objective_id = objective_id.clone();
        handles.push(std::thread::spawn(move || -> String {
            let context =
                PlannerEngineContext::new(80_000, BTreeSet::new(), AStarCostWeights::default());
            let mut first = None::<String>;
            for seq in 0..requests_per_worker {
                let request = PlanRequest::new(
                    objective_id.clone(),
                    PlanRequestMode::Plan,
                    &format!("integration.concurrent.{worker}.{seq}"),
                    None,
                    false,
                )
                .expect("request");
                let output = engine.execute(&request, &context).expect("plan");
                let fingerprint = result_fingerprint(&output.result);
                match first.as_ref() {
                    Some(existing) => assert_eq!(existing, &fingerprint),
                    None => first = Some(fingerprint),
                }
            }
            first.expect("fingerprint")
        }));
    }

    let mut fingerprints = BTreeSet::new();
    for handle in handles {
        fingerprints.insert(handle.join().expect("join"));
    }
    assert_eq!(fingerprints.len(), 1);
}
