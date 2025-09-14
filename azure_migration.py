#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Azure Migration Assessor – unified, auto, read-only

Outputs:
1) azure_env_discovery_<ts>.csv        -> Subscription ID, Sub. Type, Sub. Owner, Transferable (Internal)
2) non_transferable_reasons_<ts>.csv   -> only non-transferables + why
3) blockers_details_<ts>.csv           -> resource-level blockers (validateMoveResources + official move-support table)

Rules:
- Always trust the official move-support table for "Subscription" support.
- If resource type supported for subscription move:
    * If it's a child → it must move with its parent (not a blocker; DO NOT output).
    * If it's top-level → not a blocker.
- If child supported but parent NOT supported → blocker (ParentNotSupported).
- If child NOT supported but parent supported → blocker (UnsupportedChildTypeCannotMove).
- If neither supported → blocker (UnsupportedResourceType).
- validateMoveResources policy/permission/lock/provider errors are always blockers and override table.
"""

import os, sys, subprocess, json, csv, re, urllib.request, logging
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

# ---------- Environment ----------
os.environ.setdefault("AZURE_CORE_NO_COLOR", "1")
os.environ.setdefault("AZURE_EXTENSION_USE_DYNAMIC_INSTALL", "yes_without_prompt")

MISSING = "Not available"
MD_LOCAL_PATH = "/mnt/data/move-support-resources.md"   # אם העלית את הדוק מקומי
CSV_FALLBACK  = "https://raw.githubusercontent.com/tfitzmac/resource-capabilities/master/move-support-resources.csv"

# ---------- AZ helpers ----------
def az(cmd: List[str], check: bool = True) -> Tuple[int,str,str]:
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
    az(["az","account","show","--only-show-errors"], check=False)

# ---------- String normalization ----------
def normalize_type(s: str) -> str:
    if not s: return ""
    t = s.strip().lower()
    t = re.sub(r"\s+", "", t)
    t = re.sub(r"/+", "/", t)
    return t

# ---------- Move-support loaders ----------
def _strip_markdown(cell: str) -> str:
    c = (cell or "")
    # drop blockquote markers and surrounding spaces
    c = re.sub(r"^\s*>\s*", "", c)
    # remove markdown bold/italics/backticks and links
    c = c.replace("**", "").replace("__", "").replace("`", "")
    c = re.sub(r"$begin:math:display$.*?$end:math:display$$begin:math:text$.*?$end:math:text$", "", c)
    c = c.strip()
    return c

def _split_md_row(line: str) -> List[str]:
    # remove leading '>' if in blockquote
    line = re.sub(r"^\s*>\s*", "", line.strip())
    if not line.startswith("|"):
        return []
    # keep empty cells but drop leading/trailing pipe
    parts = line.strip().strip("|").split("|")
    return [p.strip() for p in parts]

def load_support_from_md(md_path: str) -> Dict[str,bool]:
    """
    Parse MS Docs markdown into map: { 'microsoft.xxx/type[/child]' : True/False } by 'Subscription' column.
    Handles:
      - tables within blockquotes (lines starting with '>')
      - provider namespace taken from '## Microsoft.Xxx' section headings
      - nested tables; bold/links in cells
    """
    if not os.path.exists(md_path):
        raise FileNotFoundError(md_path)

    with open(md_path, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    support: Dict[str,bool] = {}
    in_table = False
    current_ns: Optional[str] = None  # 'microsoft.web', etc.

    # helper
    def yesno(cell: str) -> Optional[bool]:
        c = _strip_markdown(cell).lower()
        if c.startswith("yes"): return True
        if c.startswith("no"):  return False
        return None

    for raw in lines:
        line = raw.rstrip()

        # track provider from section headers like "## Microsoft.Web" (case-insensitive)
        m_hdr = re.match(r"^\s*#\#\s*([Mm]icrosoft\.[A-Za-z0-9]+)\s*$", re.sub(r"^\s*>\s*", "", line))
        if m_hdr:
            current_ns = normalize_type(m_hdr.group(1))
            continue

        # detect table header (possibly with leading '>')
        header = re.sub(r"^\s*>\s*", "", line.strip())
        if re.match(r'^\|\s*resource\s*type\s*\|\s*resource\s*group\s*\|\s*subscription\s*\|\s*region\s*move\s*\|', header, re.IGNORECASE):
            in_table = True
            continue

        if in_table:
            # allow separator row or header repeats
            sep = re.sub(r"^\s*>\s*", "", line.strip())
            if re.match(r'^\|\s*-+\s*\|\s*-+\s*\|\s*-+\s*\|\s*-+\s*\|$', sep):
                continue
            if not line.strip().startswith("|") and not line.strip().startswith("> |"):
                # table ended
                in_table = False
                continue

            cols = _split_md_row(line)
            if len(cols) < 4:
                continue

            rtype_cell = _strip_markdown(cols[0])
            subscription_cell = cols[2]

            # Skip header rows inside table
            if re.match(r"^\s*resource\s*type\s*$", rtype_cell, re.IGNORECASE):
                continue

            # Normalize type: may be either fully-qualified ("microsoft.web/sites") or short ("sites")
            rt = normalize_type(rtype_cell)
            if not rt:
                continue

            if "/" not in rt:
                # short form – need current_ns
                if not current_ns:
                    # can't resolve without namespace; skip safely
                    continue
                key = f"{current_ns}/{rt}"
            else:
                key = rt

            yn = yesno(subscription_cell)
            if yn is None:
                # no explicit yes/no (e.g., pending/manual text) → skip
                continue

            support[key] = yn

    if not support:
        raise ValueError("Parsed markdown but found no support rows.")
    return support

def load_support_from_csv(url: str) -> Dict[str,bool]:
    support: Dict[str,bool] = {}
    with urllib.request.urlopen(url) as resp:
        text = resp.read().decode("utf-8").splitlines()
    rdr = csv.DictReader(text)
    for row in rdr:
        ns  = normalize_type(row.get("resourceProvider") or "")
        rt  = normalize_type(row.get("resourceType") or "")
        if not ns or not rt:
            continue
        key = f"{ns}/{rt}"
        sub_ok = ((row.get("subscription") or "").strip().lower().startswith("yes"))
        support[key] = sub_ok
    if not support:
        raise ValueError("CSV support map is empty.")
    return support

def load_move_support_map() -> Dict[str,bool]:
    try:
        logging.info(f"Loading move-support from MD: {MD_LOCAL_PATH}")
        return load_support_from_md(MD_LOCAL_PATH)
    except Exception as e:
        logging.warning(f"MD parse failed ({e}); falling back to CSV: {CSV_FALLBACK}")
        return load_support_from_csv(CSV_FALLBACK)

# ---------- Offer / Owner / Transferability ----------
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

# ---------- Inventory & validation ----------
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
        if r.get("type") in non_movable: continue
        rg=r.get("rg"); rid=r.get("id")
        if rg and rid: grouped.setdefault(rg, []).append(rid)
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
        try: return json.loads(out)
        except Exception: return {}
    return {"error":{"code":"ValidationFailed","message": err or "Validation failed"}}

# ---------- Parse resource IDs / child detection ----------
def parse_types(resource_id: str):
    """
    Returns: is_child, top_level_type, full_type, parent_id, parent_type
    Example:
      .../providers/Microsoft.Web/sites/myapp/slots/stage
      -> top = microsoft.web/sites
         full = microsoft.web/sites/slots
         parent_id = .../providers/Microsoft.Web/sites/myapp
         parent_type = microsoft.web/sites
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

# ---------- Table-driven classification ----------
def classify_support(resource_id: str, support: Dict[str,bool]) -> Dict[str,Any]:
    """
    Pure table logic (no ARM errors). Returns {} when everything is OK (not a blocker),
    or a dict describing the blocker otherwise.
    """
    is_child, top_type, full_type, parent_id, parent_type = parse_types(resource_id)
    top_ok  = support.get(top_type or "", None)
    full_ok = support.get(full_type or "", None)

    # Effective support for the resource itself: prefer child-specific line, else fallback to parent line
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

    # Supported → only check parent if child
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
        return {}  # OK (don’t output)

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

# ---------- Generic ARM error → blocker ----------
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
        return ("InsufficientPermissions","Caller lacks required permissions on source/destination.","Ensure 'moveResources' on source RG + write on target RG")
    if "child" in m and "parent" in m:
        return ("CrossRGParentChildDependency","Child must move with its parent (or vice versa).","Move together / unify RG first")
    if "cannot be moved" in m or "is not supported for move" in m:
        return ("UnsupportedResourceType","Resource type/SKU isn’t supported for move.","See move-support table")
    return ("ValidationFailed","Azure returned a validation failure. Inspect details JSON.","See ARM move guidance")

# ---------- Main ----------
def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    ensure_login()

    # Load official move-support (MD first, then CSV fallback)
    try:
        support_map = load_move_support_map()
        logging.info(f"Loaded {len(support_map)} resource-type rows into support map.")
    except Exception as e:
        logging.error(f"Failed to load move-support table: {e}")
        support_map = {}

    # Discovery headers (same columns as the “old script”)
    headers_discovery = ["Subscription ID","Sub. Type","Sub. Owner","Transferable (Internal)"]
    headers_reasons   = ["Subscription ID","Sub. Type","ReasonCode","Why","DocRef"]
    headers_blockers  = ["SubscriptionId","ResourceGroup","ResourceId","ResourceType","IsChild","ParentId","ParentType","BlockerCategory","Why","DocRef"]

    subs = az_json(["az","account","list","--all","-o","json"], [])
    billing_accounts = az_json(["az","billing","account","list","-o","json"], [])
    overall_agreement = ""
    try: overall_agreement = (billing_accounts[0].get("agreementType") or "")
    except Exception: pass

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_discovery = f"azure_env_discovery_{ts}.csv"
    out_reasons   = f"non_transferable_reasons_{ts}.csv"
    out_blockers  = f"blockers_details_{ts}.csv"

    rows_discovery=[]; rows_reasons=[]
    non_transferable_subs: List[str] = []

    # -------- Stage 1: discovery --------
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

    # -------- Stage 2: blockers (only for non-transferable subs) --------
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

            # Single ARM validation call for the whole RG batch
            result = validate_move_resources(sub_id, src_rg, ids, target_rg_id)

            if isinstance(result, dict) and "error" in result:
                # Global ARM error → apply same blocker to all resources in the batch
                cat, why, doc = blocker_from_arm_error(result["error"])
                for rid in ids:
                    blockers_rows.append([
                        sub_id, src_rg, rid, "", "", "", "", cat, why, doc
                    ])
                continue

            # No global ARM error → table-driven classification per resource
            for rid in ids:
                cls = classify_support(rid, support_map)
                if cls:  # only blockers ({} means OK)
                    blockers_rows.append([
                        sub_id,
                        src_rg,
                        rid,
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
