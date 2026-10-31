"""backend/resolve/cluster.py
Constrained Union-Find Clustering and Golden Identity Synthesis for Kavach v2.

Enforces strict hard invariant:
    NEVER merge two records with different non-null employee IDs,
    regardless of name similarity, email similarity, or nickname matching.
"""
from __future__ import annotations

import hashlib
from typing import Any

from core.models import (
    AccountLink,
    CanonicalAccount,
    CanonicalIdentity,
    GoldenIdentity,
    ReviewQueueItem,
)


class ConstrainedUnionFind:
    """Disjoint-set forest with rank-based union, path compression,

    and strict non-merge invariants across conflicting employee IDs.
    """

    def __init__(self) -> None:
        self.parent: dict[str, str] = {}
        self.rank: dict[str, int] = {}
        # Stores canonical employee_id associated with each cluster root
        self.cluster_emp: dict[str, str | None] = {}
        # Refused unions due to constraints
        self.refused_merges: list[dict[str, Any]] = []

    def add(self, item_id: str, employee_id: str | None = None) -> None:
        clean_emp = str(employee_id).strip().lower() if employee_id else None
        if clean_emp == "":
            clean_emp = None

        if item_id not in self.parent:
            self.parent[item_id] = item_id
            self.rank[item_id] = 0
            self.cluster_emp[item_id] = clean_emp

    def find(self, item_id: str) -> str:
        if item_id not in self.parent:
            self.add(item_id)
            return item_id

        path: list[str] = []
        curr = item_id
        while self.parent[curr] != curr:
            path.append(curr)
            curr = self.parent[curr]

        for node in path:
            self.parent[node] = curr
        return curr

    def can_union(self, item_a: str, item_b: str) -> tuple[bool, str | None]:
        root_a = self.find(item_a)
        root_b = self.find(item_b)

        if root_a == root_b:
            return True, None

        emp_a = self.cluster_emp.get(root_a)
        emp_b = self.cluster_emp.get(root_b)

        if emp_a and emp_b and emp_a != emp_b:
            reason = f"Refused: conflicting employee IDs ('{emp_a}' vs '{emp_b}')"
            return False, reason

        return True, None

    def union(
        self,
        item_a: str,
        item_b: str,
        score: float = 1.0,
        reasons: list[str] | None = None,
    ) -> bool:
        root_a = self.find(item_a)
        root_b = self.find(item_b)

        if root_a == root_b:
            return True

        allowed, refusal_reason = self.can_union(item_a, item_b)
        if not allowed:
            self.refused_merges.append({
                "item_a": item_a,
                "item_b": item_b,
                "score": score,
                "reason": refusal_reason or "Conflicting employee IDs",
            })
            return False

        # Union by rank
        emp_a = self.cluster_emp.get(root_a)
        emp_b = self.cluster_emp.get(root_b)
        merged_emp = emp_a or emp_b

        if self.rank[root_a] < self.rank[root_b]:
            self.parent[root_a] = root_b
            self.cluster_emp[root_b] = merged_emp
        elif self.rank[root_a] > self.rank[root_b]:
            self.parent[root_b] = root_a
            self.cluster_emp[root_a] = merged_emp
        else:
            self.parent[root_b] = root_a
            self.rank[root_a] += 1
            self.cluster_emp[root_a] = merged_emp

        return True

    def get_clusters(self) -> dict[str, list[str]]:
        clusters: dict[str, list[str]] = {}
        for item in self.parent:
            root = self.find(item)
            clusters.setdefault(root, []).append(item)
        return clusters


def build_golden_clusters(
    identities: list[CanonicalIdentity],
    accounts: list[CanonicalAccount],
    scored_pairs: list[dict[str, Any]],
    auto_merge_threshold: float = 0.90,
    review_threshold: float = 0.70,
) -> tuple[list[GoldenIdentity], list[AccountLink], list[ReviewQueueItem], list[dict[str, Any]]]:
    """Execute constrained clustering and synthesize golden identity graphs.

    Parameters:
    - identities: HR canonical identity records
    - accounts: System account records
    - scored_pairs: list of {id_a, id_b, score, reasons, rec_a, rec_b}
    - auto_merge_threshold: minimum score to automatically merge in union-find (>= 0.90)
    - review_threshold: minimum score to route to human review queue (0.70 to 0.90)

    Returns:
    - golden_identities: list[GoldenIdentity]
    - account_links: list[AccountLink]
    - review_queue: list[ReviewQueueItem]
    - refused_merges: list[dict[str, Any]]
    """
    cuf = ConstrainedUnionFind()

    id_lookup: dict[str, CanonicalIdentity] = {f"id:{i.identity_id}": i for i in identities}
    acc_lookup: dict[str, CanonicalAccount] = {f"acc:{a.account_id}": a for a in accounts}

    # 1. Register all records into ConstrainedUnionFind
    for key, ident in id_lookup.items():
        cuf.add(key, ident.employee_id)

    for key, acc in acc_lookup.items():
        cuf.add(key, acc.employee_id_hint)

    # 2. Sort candidate pairs descending by score so strongest evidence merges first
    sorted_pairs = sorted(scored_pairs, key=lambda p: float(p.get("score", 0.0)), reverse=True)

    link_metadata: dict[tuple[str, str], dict[str, Any]] = {}
    review_queue: list[ReviewQueueItem] = []

    for pair in sorted_pairs:
        id_a = str(pair["id_a"])
        id_b = str(pair["id_b"])
        score = float(pair.get("score", 0.0))
        reasons = list(pair.get("reasons", []))

        # Check score band
        if score >= auto_merge_threshold:
            success = cuf.union(id_a, id_b, score=score, reasons=reasons)
            if success:
                link_metadata[(id_a, id_b)] = {"score": score, "reasons": reasons}
                link_metadata[(id_b, id_a)] = {"score": score, "reasons": reasons}
        elif score >= review_threshold:
            # Check constraint: don't even propose review if hard employee_id conflict
            can_merge, _ = cuf.can_union(id_a, id_b)
            if can_merge:
                # Add to review queue
                acc_key = id_a if id_a.startswith("acc:") else (id_b if id_b.startswith("acc:") else None)
                ident_key = id_a if id_a.startswith("id:") else (id_b if id_b.startswith("id:") else None)

                item_id = hashlib.sha256(f"{id_a}:{id_b}:{score}".encode()).hexdigest()[:16]
                review_queue.append(
                    ReviewQueueItem(
                        item_id=f"rev_{item_id}",
                        account_id=acc_key[4:] if acc_key else id_a,
                        suggested_identity_id=ident_key[3:] if ident_key else id_b,
                        confidence=score,
                        reasons=reasons,
                        account_details=pair.get("rec_a", {}) if id_a == acc_key else pair.get("rec_b", {}),
                        identity_details=pair.get("rec_a", {}) if id_a == ident_key else pair.get("rec_b", {}),
                        status="pending",
                    )
                )

    # 3. Build Golden Identities and Account Links from clusters
    raw_clusters = cuf.get_clusters()
    golden_identities: list[GoldenIdentity] = []
    account_links: list[AccountLink] = []

    for root_key, members in raw_clusters.items():
        ident_members = [id_lookup[m] for m in members if m in id_lookup]
        acc_members = [acc_lookup[m] for m in members if m in acc_lookup]

        # Determine golden identity anchor
        if ident_members:
            # Anchor on primary HR identity
            primary_ident = ident_members[0]
            gid = primary_ident.identity_id
            name = primary_ident.full_name or primary_ident.email or f"User {gid}"
            email = primary_ident.email
            emp_id = primary_ident.employee_id
            dept = primary_ident.department
            job = primary_ident.job_title
            status = primary_ident.employment_status or "active"
            sources = list({i.source for i in ident_members} | {a.source for a in acc_members})
            is_hr_backed = True
        else:
            # Synthesize identity from accounts
            first_acc = acc_members[0] if acc_members else None
            if not first_acc:
                continue
            gid = f"gid_{hashlib.sha256(first_acc.account_id.encode()).hexdigest()[:12]}"
            name = first_acc.username
            email = first_acc.email
            emp_id = first_acc.employee_id_hint
            dept = None
            job = None
            status = "unlinked"
            sources = list({a.source for a in acc_members})
            is_hr_backed = False

        linked_acc_ids = [a.account_id for a in acc_members]

        golden = GoldenIdentity(
            identity_id=gid,
            canonical_name=name,
            primary_email=email,
            employee_id=emp_id,
            department=dept,
            job_title=job,
            employment_status=status,
            linked_account_ids=linked_acc_ids,
            confidence=1.0 if is_hr_backed else 0.85,
            sources=sources,
            extra={"hr_backed": is_hr_backed, "cluster_size": len(members)},
        )
        golden_identities.append(golden)

        # Generate AccountLink records
        for acc in acc_members:
            acc_key = f"acc:{acc.account_id}"
            # Find evidence reasons
            best_conf = 1.0 if is_hr_backed else 0.85
            reasons = ["Clustered identity link"]

            for ident in ident_members:
                meta = link_metadata.get((acc_key, f"id:{ident.identity_id}"))
                if meta:
                    best_conf = meta["score"]
                    reasons = meta["reasons"]
                    break

            account_links.append(
                AccountLink(
                    account_id=acc.account_id,
                    identity_id=gid,
                    system=acc.system,
                    username=acc.username,
                    confidence=best_conf,
                    reasons=reasons,
                    is_manual=False,
                    status="linked",
                )
            )

    return golden_identities, account_links, review_queue, cuf.refused_merges
