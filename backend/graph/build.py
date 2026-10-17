"""
backend/graph/build.py — NetworkX DiGraph builder from CanonicalBundle.

Constructs an enterprise identity access graph with nodes:
  identity, account, entitlement, system, resource, role
and edges:
  has_account, grants, access_to, contains, accessed, can_assume
"""
from __future__ import annotations

import networkx as nx
from core.models import CanonicalBundle


def build_identity_graph(bundle: CanonicalBundle) -> nx.DiGraph:
    """
    Builds a directed access graph from the canonical bundle.
    Edge weights represent traversal difficulty/cost (lower cost = easier/higher privilege).
    """
    g = nx.DiGraph()

    # 1. Identity Nodes
    for identity in bundle.identities:
        node_id = f"identity:{identity.identity_id}"
        g.add_node(
            node_id,
            node_type="identity",
            label=identity.full_name or identity.identity_id,
            identity_id=identity.identity_id,
            department=identity.department or "Unknown",
            job_title=identity.job_title or "Employee",
            status=identity.employment_status.value if hasattr(identity.employment_status, "value") else str(identity.employment_status),
            source=identity.source,
        )

    # Map username/email/employee_id to identity_id for fast account linking
    id_by_emp_id = {i.employee_id: f"identity:{i.identity_id}" for i in bundle.identities if i.employee_id}
    id_by_email = {i.email.lower(): f"identity:{i.identity_id}" for i in bundle.identities if i.email}

    # 2. System Nodes
    system_sensitivities = {}
    for sys in bundle.systems:
        node_id = f"system:{sys.system}"
        sens = sys.sensitivity.value if hasattr(sys.sensitivity, "value") else str(sys.sensitivity)
        system_sensitivities[sys.system] = sens
        g.add_node(
            node_id,
            node_type="system",
            label=sys.system,
            system_name=sys.system,
            sensitivity=sens,
            is_crown=(sens == "crown"),
            owner=sys.owner or "Security Operations",
        )

    # 3. Account Nodes & has_account Edges
    for acc in bundle.accounts:
        acc_node_id = f"account:{acc.account_id}"
        priv = acc.privilege_level.value if hasattr(acc.privilege_level, "value") else str(acc.privilege_level)
        status_val = acc.status.value if hasattr(acc.status, "value") else str(acc.status)
        type_val = acc.account_type.value if hasattr(acc.account_type, "value") else str(acc.account_type)

        g.add_node(
            acc_node_id,
            node_type="account",
            label=acc.username,
            account_id=acc.account_id,
            username=acc.username,
            system=acc.system,
            privilege_level=priv,
            status=status_val,
            account_type=type_val,
            last_login=acc.last_login.isoformat() if hasattr(acc.last_login, "isoformat") else acc.last_login,
            mfa_enabled=acc.mfa_enabled,
        )

        # Link to Identity
        parent_id = None
        if acc.employee_id_hint and acc.employee_id_hint in id_by_emp_id:
            parent_id = id_by_emp_id[acc.employee_id_hint]
        elif acc.email and acc.email.lower() in id_by_email:
            parent_id = id_by_email[acc.email.lower()]

        if parent_id and parent_id in g:
            g.add_edge(parent_id, acc_node_id, edge_type="has_account", weight=1.0)

        # Ensure account's system node exists
        sys_node_id = f"system:{acc.system}"
        if sys_node_id not in g:
            g.add_node(
                sys_node_id,
                node_type="system",
                label=acc.system,
                system_name=acc.system,
                sensitivity="medium",
                is_crown=False,
                owner="IT Operations",
            )

    # 4. Entitlements & grants Edges
    for ent in bundle.entitlements:
        ent_node_id = f"entitlement:{ent.system}:{ent.entitlement}"
        weight = float(ent.privilege_weight if ent.privilege_weight is not None else 5)

        if ent_node_id not in g:
            g.add_node(
                ent_node_id,
                node_type="entitlement",
                label=ent.entitlement,
                entitlement_name=ent.entitlement,
                system=ent.system,
                privilege_weight=weight,
                last_used=ent.last_used.isoformat() if hasattr(ent.last_used, "isoformat") else ent.last_used,
            )

        acc_node_id = f"account:{ent.account_id}"
        if acc_node_id in g:
            # High privilege = lower cost/weight for attack path shortest path traversal
            traversal_cost = max(0.1, 10.0 - weight)
            g.add_edge(acc_node_id, ent_node_id, edge_type="grants", weight=traversal_cost)

        # Link entitlement to its system
        sys_node_id = f"system:{ent.system}"
        if sys_node_id in g:
            g.add_edge(ent_node_id, sys_node_id, edge_type="access_to", weight=1.0)

    # 5. Resources from Events & accessed Edges
    seen_resources = set()
    for ev in bundle.events:
        if not ev.resource:
            continue
        res_key = f"{ev.system or 'default'}:{ev.resource}"
        sens = ev.resource_sensitivity.value if hasattr(ev.resource_sensitivity, "value") else str(ev.resource_sensitivity or "medium")
        res_node_id = f"resource:{res_key}"

        if res_key not in seen_resources:
            seen_resources.add(res_key)
            g.add_node(
                res_node_id,
                node_type="resource",
                label=ev.resource,
                resource_name=ev.resource,
                system=ev.system or "default",
                sensitivity=sens,
                is_crown=(sens == "crown"),
            )
            # Link system to resource
            if ev.system:
                sys_node = f"system:{ev.system}"
                if sys_node in g:
                    g.add_edge(sys_node, res_node_id, edge_type="contains", weight=0.5)

        # Link account (user_key) to resource if it was accessed
        acc_node_id = f"account:{ev.user_key}"
        if acc_node_id in g and res_node_id in g:
            if not g.has_edge(acc_node_id, res_node_id):
                g.add_edge(acc_node_id, res_node_id, edge_type="accessed", weight=1.0)

    return g
