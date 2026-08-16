"""Streamlit analyst workbench for the AI Data Center Security Digital Twin."""

import pandas as pd
import streamlit as st

from digital_twin.attack_surface import trust_chokepoints
from digital_twin.attacks import get_scenario, scenario_names
from digital_twin.counterfactual import simulate_compromise
from digital_twin.resilience import CONTROL_CATALOG, evaluate_resilience
from digital_twin.scoring import overall_risk, score_assets
from digital_twin.telemetry import generate_normal_telemetry, inject_attack_telemetry, top_anomalies
from digital_twin.topology import build_default_twin


st.set_page_config(page_title="AI Data Center Security Digital Twin", page_icon="🧠", layout="wide")
st.title("AI Data Center Security Digital Twin")
st.caption("Synthetic GPU-fabric security simulation · attack paths · blast radius · anomaly analytics · resilience")

scenario = st.sidebar.selectbox("Attack scenario", scenario_names(), index=scenario_names().index("bmc_compromise"))
max_hops = st.sidebar.slider("Blast-radius hops", 1, 6, 3)

twin = build_default_twin()
events = inject_attack_telemetry(generate_normal_telemetry(), scenario)
risks = score_assets(twin, events, scenario)
scenario_steps = get_scenario(scenario)
default_start = scenario_steps[0].asset_id
asset_ids = sorted(twin.assets)
start_asset = st.sidebar.selectbox("Counterfactual start asset", asset_ids, index=asset_ids.index(default_start))
blast = simulate_compromise(twin, start_asset, max_hops=max_hops)
resilience = evaluate_resilience(twin, scenario, start_asset, max_hops=max_hops)

m1, m2, m3, m4, m5, m6 = st.columns(6)
m1.metric("Assets", len(twin.assets))
m2.metric("GPU nodes", twin.summary().get("gpu_node", 0))
m3.metric("GPUs", twin.summary().get("gpu", 0))
m4.metric("Overall risk", f"{overall_risk(risks):.3f}")
m5.metric("Blast score", f"{blast.blast_score:.3f}")
m6.metric("Residual blast", f"{resilience.residual_blast_score:.3f}")

t1, t2, t3, t4, t5, t6, t7 = st.tabs(
    [
        "Digital Twin",
        "Attack Path",
        "Risk & Telemetry",
        "Blast Radius",
        "Trust Chokepoints",
        "Control What-if",
        "Counterfactual Actions",
    ]
)

with t1:
    st.subheader("Asset topology")
    asset_rows = [
        {
            "asset_id": asset.asset_id,
            "kind": asset.kind,
            "zone": asset.zone,
            "criticality": asset.criticality,
            "privileged": asset.privileged,
            "internet_exposed": asset.internet_exposed,
            "connections": len(twin.neighbors(asset.asset_id)),
        }
        for asset in twin.assets.values()
    ]
    df = pd.DataFrame(asset_rows)
    c1, c2 = st.columns([2, 1])
    with c1:
        st.dataframe(df.sort_values(["criticality", "connections"], ascending=False), use_container_width=True, hide_index=True)
    with c2:
        st.bar_chart(df.groupby("kind").size().sort_values(ascending=False))
        st.write("**Zones**")
        st.bar_chart(df.groupby("zone").size())

with t2:
    st.subheader(f"Simulated path — {scenario.replace('_', ' ').title()}")
    path_df = pd.DataFrame(
        [
            {
                "step": step.order,
                "asset": step.asset_id,
                "objective": step.objective,
                "action": step.action,
                "ATT&CK-style mapping": step.technique,
            }
            for step in scenario_steps
        ]
    )
    st.dataframe(path_df, use_container_width=True, hide_index=True)
    st.markdown(" → ".join(f"**{step.asset_id}**" for step in scenario_steps))

with t3:
    st.subheader("Explainable risk and anomaly evidence")
    risk_df = pd.DataFrame(
        [
            {
                "asset": item.asset_id,
                "risk": item.risk,
                "criticality": item.criticality,
                "anomaly": item.anomaly,
                "connectivity": item.connectivity,
                "attack_path": bool(item.scenario_exposure),
                "reasons": ", ".join(item.reasons),
            }
            for item in risks
        ]
    )
    st.dataframe(risk_df.head(20), use_container_width=True, hide_index=True)
    st.bar_chart(risk_df.head(12).set_index("asset")[["risk", "anomaly"]])

    anomaly_rows = [
        {
            "minute": event.minute,
            "source": event.source,
            "metric": event.metric,
            "value": event.value,
            "anomaly_score": score,
            "detail": event.detail,
        }
        for event, score in top_anomalies(events, limit=12)
    ]
    st.write("**Top telemetry anomalies**")
    st.dataframe(pd.DataFrame(anomaly_rows), use_container_width=True, hide_index=True)

with t4:
    st.subheader(f"Blast radius if `{start_asset}` is compromised")
    b1, b2, b3, b4, b5 = st.columns(5)
    b1.metric("Reachable assets", blast.reachable_assets)
    b2.metric("Critical assets", blast.critical_assets)
    b3.metric("GPU nodes", blast.gpu_nodes)
    b4.metric("GPUs", blast.gpus)
    b5.metric("Models", blast.models)
    impacted_df = pd.DataFrame(
        [
            {
                "asset": asset_id,
                "kind": twin.assets[asset_id].kind,
                "zone": twin.assets[asset_id].zone,
                "criticality": twin.assets[asset_id].criticality,
            }
            for asset_id in blast.impacted
        ]
    )
    st.dataframe(impacted_df.sort_values("criticality", ascending=False), use_container_width=True, hide_index=True)

with t5:
    st.subheader("Systemic trust chokepoints")
    st.write(
        "Chokepoint analysis combines asset criticality, graph degree, privileged surface, "
        "and articulation-point status. It highlights assets whose failure or compromise can "
        "change reachability across the twin."
    )
    choke_rows = [
        {
            "asset": row.asset_id,
            "kind": row.kind,
            "degree": row.degree,
            "criticality": row.criticality,
            "articulation_point": row.articulation_point,
            "chokepoint_score": row.chokepoint_score,
        }
        for row in trust_chokepoints(twin, limit=15)
    ]
    choke_df = pd.DataFrame(choke_rows)
    st.dataframe(choke_df, use_container_width=True, hide_index=True)
    st.bar_chart(choke_df.head(10).set_index("asset")[["chokepoint_score", "criticality"]])

with t6:
    st.subheader("Defensive control what-if")
    st.write(
        "The control model asks a different counterfactual question: if specific preventive "
        "controls are assumed effective, how much residual systemic risk remains? Effectiveness "
        "values are illustrative and are never presented as empirical breach probabilities."
    )
    r1, r2, r3, r4 = st.columns(4)
    r1.metric("Raw blast", f"{resilience.raw_blast_score:.3f}")
    r2.metric("Control reduction", f"{resilience.control_reduction:.1%}")
    r3.metric("Residual blast", f"{resilience.residual_blast_score:.3f}")
    r4.metric("Resilience", f"{resilience.resilience_score:.3f}")

    control_rows = [
        {
            "control": control.control_id,
            "description": control.description,
            "effectiveness_assumption": control.effectiveness,
            "active_for_scenario": control.control_id in resilience.active_controls,
            "scenarios": ", ".join(control.scenarios),
        }
        for control in CONTROL_CATALOG
    ]
    st.dataframe(pd.DataFrame(control_rows), use_container_width=True, hide_index=True)

with t7:
    st.subheader("Defensive response recommendations")
    for recommendation in blast.recommendations:
        st.success(recommendation)
    st.warning("Recommendations are simulated/read-only. This project never executes containment actions.")

st.divider()
st.caption("All assets, telemetry, attack paths, identities, workloads, model artifacts, and control-effectiveness assumptions are synthetic.")
