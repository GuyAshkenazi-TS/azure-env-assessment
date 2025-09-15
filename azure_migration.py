#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Azure Migration Assessor – single-file, read-only

- Tries to load move-support table from up-to-date MS Docs (Markdown, RAW URL).
- Falls back to your repo CSV if MS Docs load/parse fails.
- No local temp files required besides outputs.

Outputs:
1) azure_env_discovery_<ts>.csv
2) non_transferable_reasons_<ts>.csv
3) blockers_details_<ts>.csv

Rules:
- Trust the support table (Subscription column) for move support.
- Child must move with parent; we don't mark supported children as blockers.
- If child supported but parent not → ParentNotSupported
- If child not supported but parent supported → UnsupportedChildTypeCannotMove
- If neither supported → UnsupportedResourceType
- Any validateMoveResources policy/permission/lock/provider errors = blockers
"""

import os, subprocess, json, csv, io, re, urllib.request, logging
from datetime import datetime
from typing import Dict, Any, List, Tuple

# ---------------- Config ----------------
os.environ.setdefault("AZURE_CORE_NO_COLOR", "1")
os.environ.setdefault("AZURE_EXTENSION_USE_DYNAMIC_INSTALL", "yes_without_prompt")

# Primary (auto-updating MS Docs RAW Markdown)
DEFAULT_MOVE_SUPPORT_URL = (
    "https://raw.githubusercontent.com/MicrosoftDocs/azure-docs/refs/heads/main/"
    "articles/azure-resource-manager/management/move-support-resources.md"
)
# Fallback (your stable CSV in repo)
DEFAULT_FALLBACK_MOVE_SUPPORT_URL = (
    "https://raw.githubusercontent.com/GuyAshkenazi-TS/azure-env-assessment/refs/heads/main/move-support-resources-local.csv"
)

# Allow overrides by environment
MOVE_SUPPORT_URL = os.getenv("MOVE_SUPPORT_URL", DEFAULT_MOVE_SUPPORT_URL)
FALLBACK_MOVE_SUPPORT_URL = os.getenv("FALLBACK_MOVE_SUPPORT_URL", DEFAULT_FALLBACK_MOVE_SUPPORT_URL)

MISSING = "Not available"

# ---------------- Basic helpers ----------------
def az(cmd: List[str], check: bool = True) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise subprocess.CalledProcessError(p.returncode, cmd, p.stdout, p.stderr)
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()

def az_json(cmd: List[str], default: Any):
    try:
        _, out, _ = az(cmd, check=False)
        return json.loads(out) if out else default
    except Exception:
        return default

def ensure_login():
    az(["az", "account", "show", "--only-show-errors"], check=False)

def normalize_type(s: str) -> str:
    if not s: return ""
    t = s.strip().lower()
    t = re.sub(r"\s+", "", t)
    t = re.sub(r"/+", "/", t)
    return t

def _pick_col(row, *candidates):
    if not row: return None
    keys = {str(k).strip().lower(): k for k in row.keys()}
    for c in candidates:
        k = keys.get(str(c).strip().lower())
        if k: return k
    return None

# ---------------- Move-support table (CSV/Markdown) ----------------
def _open_url_or_file(url: str) -> str:
    # Supports http(s) and local files transparently
    if re.match(r"^https?://", url, re.IGNORECASE):
        with urllib.request.urlopen(url) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    with open(url, "r", encoding="utf-8") as f:
        return f.read()

def _normalize_type(s: str) -> str:
    if not s: return ""
    t = s.strip().lower()
    t = re.sub(r"\s+", "", t)
    t = re.sub(r"/+", "/", t)
    return t

def _parse_md_tables(md_text: str) -> List[List[str]]:
    lines = md_text.splitlines()
    tables, cur, in_table = [], [], False
    for ln in lines:
        if ln.strip().startswith("|") and "|" in ln.strip()[1:]:
            cur.append(ln.rstrip())
            in_table = True
        else:
            if in_table:
                tables.append(cur); cur=[]; in_table=False
    if in_table and cur:
        tables.append(cur)
    return tables

def _parse_md_table_to_dicts(md_lines: List[str]) -> List[Dict[str,str]]:
    if not md_lines: return []
    header = [c.strip() for c in md_lines[0].strip("|").split("|")]
    start = 1
    if len(md_lines) > 1 and set(md_lines[1].replace("|","").strip()) <= set("-: "):
        start = 2
    rows = []
    for ln in md_lines[start:]:
        cells = [c.strip() for c in ln.strip("|").split("|")]
        if len(cells) != len(header):
            if len(cells) < len(header):
                cells += [""] * (len(header)-len(cells))
            else:
                cells = cells[:len(header)]
        rows.append(dict(zip(header, cells)))
    return rows

def load_move_support_map_from_md(url: str) -> Dict[str, bool]:
    text = _open_url_or_file(url)
    support: Dict[str,bool] = {}

    def _contains(h: str, needle: str) -> bool:
        return needle in h.strip().lower()

    for t in _parse_md_tables(text):
        rows = _parse_md_table_to_dicts(t)
        if not rows:
            continue

        headers = list(rows[0].keys())
        # היה כאן == "subscription" – מחליפים ל-"subscription" in header
        has_sub = any(_contains(h, "subscription") for h in headers)
        has_provider = any(_contains(h, "resourceprovider") or _contains(h, "provider") or _contains(h, "namespace") or _contains(h, "rp") for h in headers)
        has_type = any(_contains(h, "resourcetype") or _contains(h, "resourcetype(s)") or _contains(h, "type") for h in headers)
        if not (has_sub and has_provider and has_type):
            continue

        for r in rows:
            # זיהוי עמודות גמיש יותר
            col_ns_candidates  = ("resourceProvider","provider","namespace","rp","Resource provider")
            col_rt_candidates  = ("resourceType","resourcetype","resourcetype(s)","type","Resource type","Resource type(s)")
            col_sub_candidates = ("subscription","subscription support","subscription_move","subscription move support")

            col_ns  = _pick_col(r, *col_ns_candidates)
            col_rt  = _pick_col(r, *col_rt_candidates)
            col_sub = _pick_col(r, *col_sub_candidates)

            ns  = _normalize_type(r.get(col_ns, "") if col_ns else "")
            rt  = _normalize_type(r.get(col_rt, "") if col_rt else "")
            sub = (r.get(col_sub, "") if col_sub else "").strip().lower()

            if not ns or not rt:
                continue

            key = f"{ns}/{rt}"
            # תומך ב-"Yes", "Yes -", "Yes (" וכו'
            support[key] = sub.startswith("yes")

        if support:
            break

    if not support:
        raise RuntimeError("Failed to parse move-support table from Markdown (no matching table with Subscription-like column).")
    return support

def load_move_support_map_from_csv(url: str) -> Dict[str, bool]:
    text = _open_url_or_file(url).replace("\r\n","\n").replace("\r","\n")
    rdr = csv.DictReader(io.StringIO(text))
    support: Dict[str,bool] = {}
    for row in rdr:
        if not row:
            continue
        col_ns  = _pick_col(row, "resourceProvider","provider","namespace","rp")
        col_rt  = _pick_col(row, "resourceType","type","resourcetype")
        col_sub = _pick_col(row, "subscription","subscription_move","subscription support")
        if not (col_ns and col_rt and col_sub):
            continue
        ns  = _normalize_type(row.get(col_ns, ""))
        rt  = _normalize_type(row.get(col_rt, ""))
        sub = (row.get(col_sub, "") or "").strip().lower()
        if not ns or not rt:
            continue
        key = f"{ns}/{rt}"
        support[key] = sub.startswith("yes")
    if not support:
        raise RuntimeError("Support map is empty after parsing CSV.")
    return support

def _load_support(url: str) -> Dict[str,bool]:
    if url.lower().endswith(".md"):
        return load_move_support_map_from_md(url)
    return load_move_support_map_from_csv(url)

def load_move_support_map() -> Dict[str, bool]:
    # Try primary URL first, then fallback
    logging.info(f"Downloading move-support table (primary): {MOVE_SUPPORT_URL}")
    try:
        return _load_support(MOVE_SUPPORT_URL)
    except Exception as e:
        logging.warning(f"Primary move-support load failed: {e}")
        logging.info(f"FALLBACK to: {FALLBACK_MOVE_SUPPORT_URL}")
        return _load_support(FALLBACK_MOVE_SUPPORT_URL)

# ---------------- Offer / Owner / Transferability ----------------
def offer_from_quota(quota_id: str, authorization_source: str, has_mca_billing_link: bool) -> str:
    q = quota_id or ""
    if any(x in q for x in ("MSDN","MS-AZR-0029P","MS-AZR-0062P","MS-AZR-0063P","VisualStudio","VS")):
        return "MSDN"
    if q == "PayAsYouGo_2014-09-01" or any(x in q for x in ("MS-AZR-0003P","MS-AZR-0017P","MS-AZR-0023P")):
        return "Pay-As-You-Go"
    if any(x in q for x in ("MS-AZR-0145P","MS-AZR-0148P","MS-AZR-0033P","MS-AZR-0034P")):
        return "EA"
    if authorization_source == "ByPartner":
        return "CSP"
    if has_mca_billing_link:
        return "MCA-online"
    return MISSING

def transferable_to_ea(offer: str) -> str:
    return "Yes" if offer in ("EA","Pay-As-You-Go") else "No"

def get_classic_account_admin_via_rest(sub_id: str) -> str:
    url = f"https://management.azure.com/subscriptions/{sub_id}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01"
    js = az_json(["az","rest","--only-show-errors","--method","get","--url",url,"-o","json"], {})
    try:
        for item in js.get("value", []):
            if (item.get("properties", {}) or {}).get("role") == "Account Administrator":
                em = (item.get("properties", {}) or {}).get("emailAddress","")
                if em: return em
    except Exception:
        pass
    return ""

def mca_billing_owner_for_sub(sub_id: str) -> str:
    bsub = az_json(["az","billing","subscription","show","--subscription-id",sub_id,"-o","json"], {})
    ba = bsub.get("billingAccountId"); bp = bsub.get("billingProfileId"); inv = bsub.get("invoiceSectionId")
    scope=None
    if ba and bp and inv: scope=f"/providers/Microsoft.Billing/billingAccounts/{ba}/billingProfiles/{bp}/invoiceSections/{inv}"
    elif ba and bp:       scope=f"/providers/Microsoft.Billing/billingAccounts/{ba}/billingProfiles/{bp}"
    elif ba:              scope=f"/providers/Microsoft.Billing/billingAccounts/{ba}"
    if not scope: return ""
    roles = az_json(["az","billing","role-assignment","list","--scope",scope,"-o","json"], [])
    for r in roles:
        if (r.get("roleDefinitionName") or "") == "Owner":
            return r.get("principalEmail") or r.get("principalName") or r.get("signInName") or ""
    return ""

def resolve_owner(sub_id: str, offer: str) -> str:
    if offer in ("MSDN","Pay-As-You-Go","EA"):
        owner = get_classic_account_admin_via_rest(sub_id)
        return owner if owner else ("Check in EA portal - Account Owner" if offer=="EA" else "Check in Portal - classic subscription")
    if offer in ("MCA-online","MCA-E"):
        owner = mca_billing_owner_for_sub(sub_id)
        return owner if owner else "Check in Billing (MCA)"
    if offer == "CSP":
        return "Managed by partner - CSP"
    return MISSING

def reason_for_non_transferable(offer: str, state: str, auth_src: str) -> Tuple[str,str,str]:
    if state and state.lower()!="enabled":
        return ("DisabledSubscription","Subscription must be Active/Enabled before transfer.","Move prerequisites")
    if offer == "CSP":
        return ("PartnerManagedNotDirectToEA","CSP → EA isn’t an automatic billing transfer; requires manual resource move.","Move resources guidance")
    if offer in ("MCA-online","MCA-E"):
        return ("ManualResourceMoveRequired","MCA → EA direct billing transfer isn’t supported; move resources into EA subscription.","Move resources guidance")
    if offer in ("MSDN", MISSING):
        return ("NotSupportedOffer","Dev/Test or classic/unknown offer isn’t supported for a direct EA transfer.","Transfer matrix")
    return ("Unknown","Insufficient data to determine blocking reason.","Check tenant/offer/permissions")

# ---------------- Inventory & validation ----------------
def list_rgs(sub_id: str) -> List[str]:
    rgs = az_json(["az","group","list","--subscription",sub_id,"-o","json"], [])
    return [rg.get("name") for rg in rgs if rg.get("name")]

def list_resources_by_rg(subscription_id: str) -> Dict[str,List[str]]:
    resources = az_json(["az","resource","list","--subscription",subscription_id,
                         "--query","[].{id:id, type:type, rg:resourceGroup}","-o","json"], [])
    non_movable = {
        "Microsoft.Network/networkWatchers",
        "Microsoft.OffAzure/VMwareSites",
        "Microsoft.OffAzure/MasterSites",
        "Microsoft.Migrate/migrateprojects",
        "Microsoft.Migrate/assessmentProjects",
    }
    grouped={}
    for r in resources:
        if r.get("type") in non_movable: 
            continue
        rg=r.get("rg"); rid=r.get("id")
        if rg and rid: 
            grouped.setdefault(rg, []).append(rid)
    return grouped

def pick_intrasub_target_rg(sub_id: str, src_rg: str, all_rgs: List[str]) -> str:
    candidates = [r for r in all_rgs if r and r.lower()!=src_rg.lower()]
    if not candidates: return ""
    for pref in ("migr","target","transit","move"):
        for r in candidates:
            if pref in r.lower(): return r
    return candidates[0]

def validate_move_resources(source_sub: str, rg: str, resource_ids: List[str], target_rg_id: str) -> Dict[str,Any]:
    body = json.dumps({"resources": resource_ids, "targetResourceGroup": target_rg_id})
    code, out, err = az(["az","resource","invoke-action","--action","validateMoveResources",
                         "--ids", f"/subscriptions/{source_sub}/resourceGroups/{rg}",
                         "--request-body", body], check=False)
    if code==0 and out:
        try: 
            return json.loads(out)
        except Exception: 
            return {}
    return {"error":{"code":"ValidationFailed","message": err or "Validation failed"}}

# ---------------- Parse types & classification ----------------
def parse_types(resource_id: str):
    """
    Returns: is_child, top_level_type, full_type, parent_id, parent_type
    ex: .../providers/Microsoft.Web/sites/myapp/slots/stage
        top = microsoft.web/sites, full = microsoft.web/sites/slots
    """
    m = re.search(r"/providers/([^/]+)/([^/]+)(/.*)?", resource_id, re.IGNORECASE)
    if not m:
        return False, None, None, None, None
    ns, t0, rest = m.group(1), m.group(2), (m.group(3) or "")
    top_type = normalize_type(f"{ns}/{t0}")
    segs = [s for s in rest.strip("/").split("/") if s]
    is_child = False
    full_type = top_type
    parent_id = None
    parent_type = top_type
    if len(segs) >= 3:
        is_child = True
        child_type = segs[1].lower()
        full_type  = f"{top_type}/{child_type}"
        parent_id = re.sub(r"(/providers/[^/]+/[^/]+/[^/]+).*", r"\1", resource_id, flags=re.IGNORECASE)
    return is_child, top_type, full_type, parent_id, parent_type

def classify_support(resource_id: str, support: Dict[str,bool]) -> Dict[str,Any]:
    is_child, top_type, full_type, parent_id, parent_type = parse_types(resource_id)
    top_ok  = support.get(top_type or "", None)
    full_ok = support.get(full_type or "", None)
    this_ok = full_ok if full_ok is not None else top_ok

    if this_ok is None:
        return {
            "BlockerCategory": "Unknown",
            "Why": "Resource type not found in official move-support table (subscription column). Review manually.",
            "DocRef": "move-support",
            "ResourceType": (full_type or top_type or ""),
            "IsChild": "Yes" if is_child else "No",
            "ParentId": parent_id or "",
            "ParentType": parent_type or "",
        }

    if this_ok is True:
        if is_child and top_ok is False:
            return {
                "BlockerCategory": "ParentNotSupported",
                "Why": "Parent resource type doesn’t support subscription move.",
                "DocRef": "move-support",
                "ResourceType": full_type or top_type or "",
                "IsChild": "Yes",
                "ParentId": parent_id or "",
                "ParentType": parent_type or "",
            }
        return {}  # OK

    # Not supported
    if is_child:
        if top_ok is True:
            return {
                "BlockerCategory":"UnsupportedChildTypeCannotMove",
                "Why":"Child resource type doesn’t support subscription move although parent does.",
                "DocRef":"move-support",
                "ResourceType": full_type or top_type or "",
                "IsChild":"Yes",
                "ParentId": parent_id or "",
                "ParentType": parent_type or "",
            }
        else:
            return {
                "BlockerCategory":"UnsupportedResourceType",
                "Why":"Neither child nor parent supports subscription move.",
                "DocRef":"move-support",
                "ResourceType": full_type or top_type or "",
                "IsChild":"Yes",
                "ParentId": parent_id or "",
                "ParentType": parent_type or "",
            }
    else:
        return {
            "BlockerCategory":"UnsupportedResourceType",
            "Why":"Resource type doesn’t support subscription move.",
            "DocRef":"move-support",
            "ResourceType": top_type or "",
            "IsChild":"No",
            "ParentId":"",
            "ParentType":"",
        }

# ---------------- ARM error mapping ----------------
def blocker_from_arm_error(err: Dict[str,Any]) -> Tuple[str,str,str]:
    m = json.dumps(err, ensure_ascii=False).lower()
    if "requestdisallowedbypolicy" in m or " policy" in m:
        if "tag" in m and "owner" in m and "email" in m:
            return ("PolicyBlocked","Required 'owner' tag with valid email (may require specific domain).","Align tags/policy and re-validate")
        return ("PolicyBlocked","Blocked by Azure Policy on source/target RG or subscription.","Align policy and re-validate")
    if "lock" in m or "readonly" in m:
        return ("ResourceLockPresent","Read-only lock on source or destination RG/subscription.","Remove lock before move")
    if ("not registered for a resource type" in m) or ("provider" in m and "register" in m):
        return ("ProviderRegistrationMissing","Destination subscription missing required Resource Provider registration.","Register provider in target subscription")
    if "authorization" in m or "not permitted" in m or "insufficient privileges" in m or "denyassignment" in m:
        return ("InsufficientPermissions","Caller lacks required permissions on source/destination.","Ensure moveResources on source RG + write on target RG")
    if "child" in m and "parent" in m:
        return ("CrossRGParentChildDependency","Child must move with its parent (or vice versa).","Move together / unify RG first")
    if "cannot be moved" in m or "is not supported for move" in m:
        return ("UnsupportedResourceType","Resource type/SKU isn’t supported for move.","See move-support table")
    return ("ValidationFailed","Azure returned a validation failure. Inspect details JSON.","See ARM move guidance")

# ---------------- Main ----------------
def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    ensure_login()

    support_map = load_move_support_map()
    logging.info(f"Loaded {len(support_map)} resource-type rows into support map.")

    headers_discovery = ["Subscription ID","Sub. Type","Sub. Owner","Transferable (Internal)"]
    headers_reasons   = ["Subscription ID","Sub. Type","ReasonCode","Why","DocRef"]
    headers_blockers  = ["SubscriptionId","ResourceGroup","ResourceId","ResourceType","IsChild","ParentId","ParentType","BlockerCategory","Why","DocRef"]

    subs = az_json(["az","account","list","--all","-o","json"], [])
    billing_accounts = az_json(["az","billing","account","list","-o","json"], [])
    overall_agreement = ""
    try:
        overall_agreement = (billing_accounts[0].get("agreementType") or "")
    except Exception:
        pass

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_discovery = f"azure_env_discovery_{ts}.csv"
    out_reasons   = f"non_transferable_reasons_{ts}.csv"
    out_blockers  = f"blockers_details_{ts}.csv"

    rows_discovery=[]; rows_reasons=[]
    non_transferable_subs: List[str] = []

    # ---- Stage 1: discovery ----
    for s in subs:
        sub_id = s.get("id",""); state = s.get("state","")
        if not sub_id: continue

        arm = az_json(["az","rest","--method","get","--url", f"https://management.azure.com/subscriptions/{sub_id}?api-version=2020-01-01","-o","json"], {})
        has_err=("error" in arm)
        quota_id = arm.get("subscriptionPolicies",{}).get("quotaId","") if not has_err else ""
        auth_src = arm.get("authorizationSource","") if not has_err else ""
        bsub = az_json(["az","billing","subscription","show","--subscription-id",sub_id,"-o","json"], {})
        has_mca = bool(bsub.get("billingAccountId")) if bsub else ("MicrosoftCustomerAgreement" in overall_agreement)

        offer = offer_from_quota(quota_id, auth_src, has_mca)
        owner = resolve_owner(sub_id, offer)
        transferable = transferable_to_ea(offer)

        rows_discovery.append([sub_id, offer, owner, transferable])

        if transferable == "No":
            code, why, doc = reason_for_non_transferable(offer, state, auth_src)
            rows_reasons.append([sub_id, offer, code, why, doc])
            non_transferable_subs.append(sub_id)

    with open(out_discovery,"w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(headers_discovery); w.writerows(rows_discovery)
    with open(out_reasons,"w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(headers_reasons); w.writerows(rows_reasons)
    print(f"✅ Discovery CSV: {out_discovery}")
    print(f"✅ Reasons   CSV: {out_reasons}")

    # ---- Stage 2: blockers ----
    blockers_rows: List[List[str]] = []

    for sub_id in non_transferable_subs:
        all_rgs = list_rgs(sub_id)
        if not all_rgs:
            logging.info(f"Skipping blockers for {sub_id}: no resource groups.")
            continue

        grouped = list_resources_by_rg(sub_id)
        if not grouped:
            logging.info(f"Skipping blockers for {sub_id}: no resources.")
            continue

        for src_rg, ids in grouped.items():
            tgt_rg = pick_intrasub_target_rg(sub_id, src_rg, all_rgs)
            if not tgt_rg:
                logging.info(f"Skipping RG '{src_rg}' in {sub_id}: no alternate target RG exists.")
                continue
            target_rg_id = f"/subscriptions/{sub_id}/resourceGroups/{tgt_rg}"

            result = validate_move_resources(sub_id, src_rg, ids, target_rg_id)

            if isinstance(result, dict) and "error" in result:
                cat, why, doc = blocker_from_arm_error(result["error"])
                for rid in ids:
                    blockers_rows.append([sub_id, src_rg, rid, "", "", "", "", cat, why, doc])
                continue

            for rid in ids:
                cls = classify_support(rid, support_map)
                if cls:
                    blockers_rows.append([
                        sub_id, src_rg, rid,
                        cls.get("ResourceType",""),
                        cls.get("IsChild","No"),
                        cls.get("ParentId",""),
                        cls.get("ParentType",""),
                        cls.get("BlockerCategory","Unknown"),
                        cls.get("Why",""),
                        cls.get("DocRef","move-support"),
                    ])

    if blockers_rows:
        with open(out_blockers,"w",newline="",encoding="utf-8") as f:
            w=csv.writer(f); w.writerow(headers_blockers); w.writerows(blockers_rows)
        print(f"🔎 Blockers CSV: {out_blockers}")
    else:
        print("🔎 Blockers scan: none detected (validateMoveResources + official move-support table).")

if __name__ == "__main__":
    main()
