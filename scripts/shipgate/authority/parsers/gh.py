"""`gh api` JSON parsing: the repository record and the environment / secrets shapes.

The repository record is the IDENTITY ANCHOR — which repository, owned by which principal, is
the subject of the decision. The environment record is where the INDEPENDENT-principal claim
lives or dies.

The captured environment is the NEGATIVE fixture, and that is the useful one:

    {"protection_rules": [], "deployment_branch_policy": null, "can_admins_bypass": true}

An environment like that is a label, not a boundary. Anyone who can push can deploy to it, and
an admin can bypass whatever it does have. `is_qualifying_environment` refuses it with
`AUT_PRINCIPAL_NOT_DISTINCT`, which is the whole point: a builder must not be able to
manufacture its own second opinion by creating an environment named "verifier".

A second, more interesting negative arrived in the 2026-08-05 capture round
(`env_protected_one.json`): a REAL protected environment, with a real `required_reviewers`
rule naming a real reviewer — and it still does not qualify, because
`prevent_self_review: false`, `can_admins_bypass: true` and `deployment_branch_policy: null`.
The argument for refusing it is in `is_qualifying_environment`; the short version is that an
approval the builder can grant itself, in an environment any admin can bypass, from any
branch, constrains nobody.

Together the two captures cover both ways an environment can look like a trust boundary
without being one: no rules at all, and rules that do not bind the builder.
"""
from ...models import reasons as R
from .. import shapes
from . import _common as C

SHAPE_REPO = "gh.repo.v1"
SHAPE_ENV = "gh.environment.v1"
SHAPE_ENV_LIST = "gh.environment.list.v1"
SHAPE_ENV_SECRETS = "gh.environment.secrets.v1"
SHAPE_ENV_PROTECTED = "gh.environment.protected.v1"

VERSION_GATE = C.VersionGate("gh", minimum=(2, 40, 0), below=(3, 0, 0), validated="v2.65.0")

#: Protection-rule types that can constitute a distinct principal. A wait_timer delays the
#: builder; it does not introduce anyone else, so it is NOT on this list.
PRINCIPAL_RULE_TYPES = ("required_reviewers",)


def _gate_version(gh_version, shape_id):
    if gh_version is None:
        return None
    supported, code, detail = VERSION_GATE.check(gh_version)
    if not supported:
        return C.fail(shape_id, code, detail)
    return None


# =======================================================================================
# repository — identity anchor
# =======================================================================================


def parse_repo(raw, gh_version=None, registry=None):
    """`gh api repos/{owner}/{repo}` -> the subject's external identity anchor."""
    reg = registry or shapes.registry()
    gated = _gate_version(gh_version, SHAPE_REPO)
    if gated is not None:
        return gated
    res, doc = C.load_json(raw, SHAPE_REPO)
    if res is not None:
        return res
    good, code, detail = shapes.validate_shape(doc, SHAPE_REPO, reg)
    if not good:
        return C.fail(SHAPE_REPO, code, detail)
    owner = doc["owner"]
    return C.ok(SHAPE_REPO, {
        "repositoryId": doc["id"],
        "nodeId": doc["node_id"],
        "fullName": doc["full_name"],
        "private": doc["private"],
        "visibility": doc["visibility"],
        "defaultBranch": doc["default_branch"],
        "htmlUrl": doc["html_url"],
        "archived": bool(doc.get("archived")),
        "owner": {
            "login": owner["login"], "id": owner["id"], "nodeId": owner["node_id"],
            "type": owner["type"],
        },
        "viewerPermissions": dict(doc["permissions"]),
    })


def check_repo_binding(repo_data, expected_full_name, shape_id=SHAPE_REPO):
    """Does this repository record describe the decision's subject repository?

    `expected_full_name` comes from the DECISION's subject, which the semantic engine already
    fixed. Comparison is case-insensitive because GitHub treats owner/repo that way, and the
    match is exact otherwise — no prefix or regex matching, which is how "org/repo-evil" gets
    accepted as "org/repo".
    """
    if not isinstance(repo_data, dict) or "fullName" not in repo_data:
        return C.unknown(shape_id, "cannot check repository binding: repo was not parsed")
    if not isinstance(expected_full_name, str) or "/" not in expected_full_name:
        return C.fail(shape_id, R.AUT_BINDING_MISMATCH,
                      f"expected repository {expected_full_name!r} is not an 'owner/name' pair")
    if repo_data["fullName"].lower() != expected_full_name.strip().lower():
        return C.fail(shape_id, R.AUT_BINDING_MISMATCH,
                      f"gh reports repository {repo_data['fullName']!r} but the decision's "
                      f"subject is {expected_full_name!r}")
    return C.ok(shape_id, {
        "kind": "github-repository",
        "fullName": repo_data["fullName"],
        "repositoryId": repo_data["repositoryId"],
        "ownerId": repo_data["owner"]["id"],
        "ownerType": repo_data["owner"]["type"],
    })


# =======================================================================================
# environments
# =======================================================================================


def parse_environment(raw, gh_version=None, registry=None):
    """`gh api repos/{o}/{r}/environments/{env}`.

    Parsing SUCCEEDS for the negative fixture — an unprotected environment is a well-formed
    fact about the world. Whether it qualifies as a trust boundary is a separate question,
    answered by `is_qualifying_environment`.
    """
    reg = registry or shapes.registry()
    gated = _gate_version(gh_version, SHAPE_ENV)
    if gated is not None:
        return gated
    res, doc = C.load_json(raw, SHAPE_ENV)
    if res is not None:
        return res
    return _environment_record(doc, reg)


def _environment_record(doc, reg):
    good, code, detail = shapes.validate_shape(doc, SHAPE_ENV, reg)
    if not good:
        return C.fail(SHAPE_ENV, code, detail)
    rules = doc["protection_rules"]
    if rules:
        # A record with rules is ALSO checked against the stricter protected schema, whose
        # rule objects are closed. An unrecognised field inside a protection rule may carry
        # semantics this kit does not model, so it is a refusal rather than a shrug.
        good, code, detail = shapes.validate_shape(doc, SHAPE_ENV_PROTECTED, reg)
        if not good:
            return C.fail(SHAPE_ENV_PROTECTED, code, detail)
    return C.ok(SHAPE_ENV, {
        "id": doc["id"],
        "nodeId": doc["node_id"],
        "name": doc["name"],
        "url": doc["url"],
        "createdAt": doc["created_at"],
        "updatedAt": doc["updated_at"],
        "canAdminsBypass": doc["can_admins_bypass"],
        "protectionRuleCount": len(rules),
        "protectionRuleTypes": [r.get("type") for r in rules if isinstance(r, dict)],
        "deploymentBranchPolicy": doc["deployment_branch_policy"],
        "raw": doc,
    })


def parse_environment_list(raw, gh_version=None, registry=None):
    """`gh api repos/{o}/{r}/environments` -> {"totalCount", "environments": [...]}"""
    reg = registry or shapes.registry()
    gated = _gate_version(gh_version, SHAPE_ENV_LIST)
    if gated is not None:
        return gated
    res, doc = C.load_json(raw, SHAPE_ENV_LIST)
    if res is not None:
        return res
    good, code, detail = shapes.validate_shape(doc, SHAPE_ENV_LIST, reg)
    if not good:
        return C.fail(SHAPE_ENV_LIST, code, detail)
    if doc["total_count"] != len(doc["environments"]):
        return C.unknown(SHAPE_ENV_LIST,
                         f"total_count {doc['total_count']} disagrees with "
                         f"{len(doc['environments'])} returned environments")
    parsed = []
    for env in doc["environments"]:
        one = _environment_record(env, reg)
        if not one.ok:
            return one
        parsed.append(one.data)
    return C.ok(SHAPE_ENV_LIST, {"totalCount": doc["total_count"], "environments": parsed})


def parse_environment_secrets(raw, gh_version=None, registry=None):
    """`gh api .../environments/{env}/secrets`.

    The captured shape is the EMPTY one. Zero secrets parses to zero — an empty environment is
    a fact, not a malformed response, and turning it into an error would hide the far more
    interesting fact that the environment holds nothing.
    """
    reg = registry or shapes.registry()
    gated = _gate_version(gh_version, SHAPE_ENV_SECRETS)
    if gated is not None:
        return gated
    res, doc = C.load_json(raw, SHAPE_ENV_SECRETS)
    if res is not None:
        return res
    good, code, detail = shapes.validate_shape(doc, SHAPE_ENV_SECRETS, reg)
    if not good:
        return C.fail(SHAPE_ENV_SECRETS, code, detail)
    if doc["total_count"] != len(doc["secrets"]):
        return C.unknown(SHAPE_ENV_SECRETS,
                         f"total_count {doc['total_count']} disagrees with "
                         f"{len(doc['secrets'])} returned secrets")
    return C.ok(SHAPE_ENV_SECRETS, {
        "totalCount": doc["total_count"],
        "names": [s["name"] for s in doc["secrets"]],
        "empty": doc["total_count"] == 0,
    })


# =======================================================================================
# the qualifying-environment question
# =======================================================================================


#: The four conditions an environment must meet, and why each one is load-bearing. This is
#: the contract; `is_qualifying_environment` is its implementation. See the module docstring
#: and references/authority-kit.md for the argument behind each.
QUALIFYING_REQUIREMENTS = (
    ("requiredReviewersRule",
     "at least one required_reviewers protection rule — a wait timer delays the builder and "
     "a branch filter constrains what it can deploy, but neither introduces another person"),
    ("nonEmptyReviewers",
     "that rule must name at least one reviewer — a required_reviewers rule with an empty "
     "reviewers array approves itself"),
    ("preventSelfReview",
     "prevent_self_review must be true — otherwise the builder can be the reviewer, and an "
     "approval you grant yourself is a confirmation dialog, not a second principal"),
    ("adminsCannotBypass",
     "can_admins_bypass must be false — a boundary that an admin can step over is not a "
     "boundary for anyone who is, or can persuade, an admin"),
    ("deploymentBranchPolicy",
     "deployment_branch_policy must be non-null — otherwise any branch, including one the "
     "builder pushed a minute ago, can reach the environment"),
)


def is_qualifying_environment(env_json, registry=None, builder_ids=()):
    """(qualifies: bool, reason_code: str|None, detail: str).

    THE DECISION, ON THE MERITS. The captured protected environment
    (`env_protected_one.json`) has a genuine `required_reviewers` rule with a genuine
    reviewer, and this function still REFUSES it. The reasoning, spelled out because it is
    the substantive judgement in this whole kit:

      * `prevent_self_review: false`. The rule names one reviewer, `OWNER`, who is the
        repository owner. Nothing stops the person who triggered the workflow from being the
        person who approves it. An approval the builder can grant itself is not a second
        principal; it is a speed bump with a UI.
      * `can_admins_bypass: true`. Any repository admin can skip the gate outright. The
        builder in this capture HAS admin (`repo.json` shows `permissions.admin: true`). A
        control the constrained party can switch off is not a control.
      * `deployment_branch_policy: null`. Any branch reaches the environment, so the builder
        chooses what is deployed as well as who approves it.

    Each of those is independently fatal, and together they mean the environment constrains
    nobody. So the answer is AUT_PRINCIPAL_NOT_DISTINCT, and it is not a technicality — an
    adopter who configured this and believed they had independent verification would be
    wrong, and finding that out from this gate is the entire point.

    What DID change when the shape was captured: the refusal is now "we have seen this shape
    and it is not a boundary" instead of "we have never seen this shape". The predicate can
    now return True — for a record that meets all of `QUALIFYING_REQUIREMENTS`.

    `builder_ids` optionally names the principals the builder can act as (e.g. the OIDC
    `actor_id` and the repository owner id). When every reviewer is in that set, the
    environment is refused even if it is otherwise perfect: a reviewer who IS the builder is
    not a distinct principal no matter what the flags say.

    Accepts raw bytes/str, an already-parsed record, or a raw gh JSON object.
    """
    reg = registry or shapes.registry()

    if isinstance(env_json, (bytes, bytearray, str)):
        parsed = parse_environment(env_json, registry=reg)
        if not parsed.ok:
            return False, parsed.reason_code, parsed.detail
        record = parsed.data
    elif isinstance(env_json, dict) and "protectionRuleCount" in env_json:
        record = env_json
    elif isinstance(env_json, dict):
        parsed = _environment_record(env_json, reg)
        if not parsed.ok:
            return False, parsed.reason_code, parsed.detail
        record = parsed.data
    else:
        return (False, R.AUT_OUTPUT_SHAPE_UNKNOWN,
                f"cannot read an environment record from {type(env_json).__name__}")

    name = record.get("name")
    rules = [r for r in (record.get("raw") or {}).get("protection_rules", ())
             if isinstance(r, dict)]
    reviewer_rules = [r for r in rules if r.get("type") in PRINCIPAL_RULE_TYPES]

    faults = []
    if record["protectionRuleCount"] == 0:
        faults.append("protection_rules is empty (nobody has to approve anything)")
    elif not reviewer_rules:
        faults.append(
            f"protection rules {record['protectionRuleTypes']} contain no "
            f"{PRINCIPAL_RULE_TYPES[0]!r} rule; a wait timer or branch filter delays the "
            "builder but introduces no other principal")

    reviewers = []
    for rule in reviewer_rules:
        for entry in rule.get("reviewers", ()) or ():
            if isinstance(entry, dict) and isinstance(entry.get("reviewer"), dict):
                reviewers.append({
                    "type": entry.get("type"),
                    "id": entry["reviewer"].get("id"),
                    "login": entry["reviewer"].get("login") or entry["reviewer"].get("slug"),
                })
    if reviewer_rules and not reviewers:
        faults.append("the required_reviewers rule names no reviewers, so it approves itself")

    self_review = [r for r in reviewer_rules if not r.get("prevent_self_review")]
    if self_review:
        faults.append(
            "prevent_self_review is false, so the builder may approve its own deployment — "
            "an approval you can grant yourself is not a second principal")

    if record["deploymentBranchPolicy"] is None:
        faults.append("deployment_branch_policy is null (any branch can deploy to it)")
    if record["canAdminsBypass"]:
        faults.append("can_admins_bypass is true (an admin can step over the boundary "
                      "entirely)")

    if builder_ids and reviewers:
        ids = {str(i) for i in builder_ids if i is not None}
        reviewer_ids = {str(r["id"]) for r in reviewers if r.get("id") is not None}
        if reviewer_ids and reviewer_ids <= ids:
            faults.append(
                f"every reviewer {sorted(reviewer_ids)} is a principal the builder already "
                "acts as; a reviewer who IS the builder is not a distinct principal")

    if faults:
        return (False, R.AUT_PRINCIPAL_NOT_DISTINCT,
                f"environment {name!r} is not a qualifying trust boundary: "
                + "; ".join(faults)
                + f". Reviewers seen: {reviewers or 'none'}.")

    return (True, None,
            f"environment {name!r} requires review by {len(reviewers)} distinct "
            f"reviewer(s) {[r['login'] for r in reviewers]}, self-review is prevented, admins "
            "cannot bypass, and a deployment branch policy is set")


def principal_from_environment(env_record, repo_binding=None):
    """Build the `principal` fact for the rule table. Only ever called after
    `is_qualifying_environment` returned True — which, in this release, never happens."""
    return {
        "kind": "github-protected-environment",
        "environment": env_record.get("name"),
        "environmentId": env_record.get("id"),
        "protectionRuleTypes": list(env_record.get("protectionRuleTypes", ())),
        "canAdminsBypass": env_record.get("canAdminsBypass"),
        "repository": (repo_binding or {}).get("fullName"),
        "distinctFromBuilder": True,
    }


__all__ = [
    "PRINCIPAL_RULE_TYPES", "QUALIFYING_REQUIREMENTS", "SHAPE_ENV", "SHAPE_ENV_LIST", "SHAPE_ENV_PROTECTED",
    "SHAPE_ENV_SECRETS", "SHAPE_REPO", "VERSION_GATE", "check_repo_binding",
    "is_qualifying_environment", "parse_environment", "parse_environment_list",
    "parse_environment_secrets", "parse_repo", "principal_from_environment",
]
