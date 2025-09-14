#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Azure Migration Assessor — single-file, runs from GitHub Raw

What it does
------------
1) Discovers subscriptions (type/owner/transferable)
2) Explains non-transferable reasons (offer/state/partner/etc.)
3) Scans resource blockers per RG using:
   - az resource invoke-action ... validateMoveResources (batch per RG)
   - Official move-support table (Subscription column) from CSV on GitHub

How to run (Linux/macOS)
------------------------
python3 - <<'PY'
# (paste this file's content here and run)
PY

OR (recommended once you push this script to your own GitHub):
curl -sSL https://raw.githubusercontent.com/<org>/<repo>/<branch>/azure_migration_assessor.py \
| python3 - --quiet

Windows (PowerShell):
iwr https://raw.githubusercontent.com/<org>/<repo>/<branch>/azure_migration_assessor.py -UseBasicParsing | `
Select-Object -Expand Content | py - --quiet

Flags
-----
--support-url  : CSV URL (default: MS official GitHub raw)
--quiet        : suppress info logs (prints only the 3 CSV paths)
--no-validate  : skip ARM validateMoveResources calls (table-only mode)
"""

import os, re, csv, json, argparse, logging, subprocess, urllib.request, urllib.error
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

# ---------------------- Args ----------------------
def parse_args():
    p = argparse.ArgumentParser(description="Azure Migration Assessor (single-file, GitHub-raw)")
    p.add_argument("--support-url",
                   default="https://raw.githubusercontent.com/tfitzmac/resource-capabilities/master/move-support-resources.csv",
                   help="GitHub raw CSV of move-support (Subscription column).")
    p.add_argument("--quiet", action="store_true", help="Quiet mode (WARN+).")
    p.add_argument("--no-validate", action="store_true",
                   help="Skip validateMoveResources calls; rely on support table only.")
    return p.parse_args()

# ---------------------- Logging / Env -------------
def setup_logging(quiet: bool):
    lvl = logging.WARNING if quiet else logging.INFO
    logging.basicConfig(level=lvl, format="%(asctime)s [%(levelname)s] %(message)s")

os.environ.setdefault("AZURE_CORE_NO_COLOR", "1")
os.environ.setdefault("AZURE_EXTENSION_USE_DYNAMIC_INSTALL", "yes_without_prompt")
MISSING = "Not available"

# ---------------------- AZ helpers ----------------
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

# ---------------------- Normalize -----------------
def normalize_type(s: str) -> str:
    if not s: return ""
    t = s.strip().lower()
    t = re.sub(r"\s+", "", t)
    t = re.sub(r"/+", "/", t)
    return t

# ---------------------- Support map (CSV) ---------
def load_move_support_map_from_url(url: str, timeout: int = 30) -> Dict[str,bool]:
    """
    Loads the official move-support table from a CSV URL and returns:
      { 'microsoft.provider/resourceType[/childType]' : True/False }
    where value is Subscription column support (Yes/No).
    """
    logging.info(f"Downloading move-support CSV from: {url}")
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", "replace").splitlines()
    except urllib.error.URLError as e:
        raise RuntimeError(f"Failed to download support CSV: {e}")

    rdr = csv.DictReader(text)
    mp: Dict[str,bool] = {}
    for row in rdr:
        ns  = normalize_type(row.get("resourceProvider") or "")
        rt  = normalize_type(row.get("resourceType") or "")
        if not ns or not rt: 
            continue
        key = f"{ns}/{rt}"
        sub_ok = (row.get("subscription","").strip().lower().startswith("yes"))
        mp[key] = sub_ok
    if not mp:
        raise RuntimeError("Support map is empty after parsing CSV.")
    logging.info(f"Loaded {len(mp)} rows into support map.")
    return mp

# ---------------------- Offer / Owner -------------
def offer_from_quota(quota_id: str, authorization_source: str, has_mca_billing_link: bool) -> str:
    q = quota_id or ""
    if any(x in q for x in ("MSDN","MS-AZR-0029P","MS-AZR-0062P","MS-AZR-0063P","VisualStudio","VS")): return "MSDN"
    if q == "PayAsYouGo_2014-09-01" or any(x in q for x in ("MS-AZR-0003P","MS-AZR-0017P","MS-AZR-0023P")): return "Pay-As-You-Go"
    if any(x in q for x in ("MS-AZR-0145P","MS-AZR-0148P","MS-AZR-0033P","MS-AZR-0034P")): return "EA"
    if authorization_source == "ByPartner": return "CSP"
    if has_mca_billing_link: return "MCA-online"
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

def resolve_owner(sub_id: str, offer: str) -> str:
    if offer in ("MSDN","Pay-As-You-Go","EA"):
        owner = get_classic_account_admin_via_rest(sub_id)
        return owner if owner else ("Check in EA portal - Account Owner" if offer=="EA" else "Check in Portal - classic subscription")
    if offer in ("MCA-online","MCA-E"):
        return "Check in Billing (MCA)"
    if offer == "CSP":
        return "Managed by partner - CSP"
    return MISSING

def reason_for_non_transferable(offer: str, state: str, auth_src: str) -> Tuple[str,str,str]:
    if state and state.lower()!="enabled":
        return ("DisabledSubscription","Subscription must be Active/Enabled before transfer.","Move prerequisites")
    if offer == "CSP":
        return ("PartnerManagedNotDirectToEA","CSP → EA requires manual resource move (no direct billing transfer).","Move resources guidance")
    if offer in ("MCA-online","MCA-E"):
        return ("ManualResourceMoveRequired","MCA → EA transfer unsupported; move resources into EA subscription.","Move resources guidance")
    if offer in ("MSDN", MISSING):
        return ("NotSupportedOffer","Dev/Test or classic/unknown offer unsupported for direct EA transfer.","Transfer matrix")
    return ("Unknown","Insufficient data to determine blocking reason.","Check tenant/offer/permissions")

# ---------------------- Inventory (live) ----------
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

def pick_intrasub_target_rg(src_rg: str, all_rgs: List[str]) -> str:
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

# ---------------------- Parse IDs -----------------
def parse_types(resource_id: str):
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

# ---------------------- Classifier ----------------
def classify_support(resource_id: str, support: Dict[str,bool]) -> Dict[str,Any]:
    is_child, top_type, full_type, parent_id, parent_type = parse_types(resource_id)
    top_ok  = support.get(top_type or "", None)
    full_ok = support.get(full_type or "", None)
    this_ok = full_ok if full_ok is not None else top_ok

    if this_ok is None:
        return {
            "BlockerCategory": "Unknown",
            "Why": "Resource type not found in official move-support table (Subscription column).",
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

    # this_ok == False
    if is_child:
        if top_ok is True:
            return {
                "BlockerCategory":"UnsupportedChildTypeCannotMove",
                "Why":"Child type doesn’t support subscription move although parent does.",
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

def blocker_from_arm_error(err: Dict[str,Any]) -> Tuple[str,str,str]:
    m = json.dumps(err, ensure_ascii=False).lower()
    if "requestdisallowedbypolicy" in m or " policy" in m:
        if "tag" in m and "owner" in m and "email" in m:
            return ("PolicyBlocked","Required 'owner' tag with valid email (possibly specific domain).","Align tags/policy and re-validate")
        return ("PolicyBlocked","Blocked by Azure Policy on source/target.","Align policy and re-validate")
    if "lock" in m or "readonly" in m:
        return ("ResourceLockPresent","Read-only lock on source/target RG/subscription.","Remove lock before move")
    if ("not registered for a resource type" in m) or ("provider" in m and "register" in m):
        return ("ProviderRegistrationMissing","Target subscription missing provider registration.","Register provider in target subscription")
    if "authorization" in m or "not permitted" in m or "insufficient privileges" in m or "denyassignment" in m:
        return ("InsufficientPermissions","Caller lacks required permissions.","Ensure moveResources on source RG + write on target RG")
    if "child" in m and "parent" in m:
        return ("CrossRGParentChildDependency","Child must move with its parent (or vice versa).","Move together / unify RG first")
    if "cannot be moved" in m or "is not supported for move" in m:
        return ("UnsupportedResourceType","Type/SKU not supported for move.","See move-support table")
    return ("ValidationFailed","Generic validation failure; check details JSON.","See ARM docs")

# ---------------------- Main ----------------------
def main():
    args = parse_args()
    setup_logging(args.quiet)

    # 1) Load move-support table from GitHub raw CSV
    support_map = load_move_support_map_from_url(args.support_url)

    # 2) Ensure az login
    ensure_login()

    # 3) Output files
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_discovery = f"azure_env_discovery_{ts}.csv"
    out_reasons   = f"non_transferable_reasons_{ts}.csv"
    out_blockers  = f"blockers_details_{ts}.csv"

    headers_discovery = ["Subscription ID","Sub. Type","Sub. Owner","Transferable (Internal)"]
    headers_reasons   = ["Subscription ID","Sub. Type","ReasonCode","Why","DocRef"]
    headers_blockers  = ["SubscriptionId","ResourceGroup","ResourceId","ResourceType","IsChild","ParentId","ParentType","BlockerCategory","Why","DocRef"]

    rows_discovery=[]; rows_reasons=[]; non_transferable_subs: List[str] = []

    # 4) Discovery per subscription
    subs = az_json(["az","account","list","--all","-o","json"], [])
    billing_accounts = az_json(["az","billing","account","list","-o","json"], [])
    overall_agreement = ""
    try: overall_agreement = (billing_accounts[0].get("agreementType") or "")
    except Exception: pass

    for s in subs:
        sub_id = s.get("id",""); state = s.get("state","")
        if not sub_id: continue

        arm = az_json(["az","rest","--method","get","--url", f"https://management.azure.com/subscriptions/{sub_id}?api-version=2020-01-01","-o","json"], {})
        has_err=("error" in arm)
        quota_id = arm.get("subscriptionPolicies",{}).get("quotaId","") if not has_err else ""
        auth_src = arm.get("authorizationSource","") if not has_err else ""
        bsub = az_json(["az","billing","subscription","show","--subscription-id",sub_id,"-o","json"], {})
        has_mca = bool(bsub.get("billingAccountId")) if bsub else ("MicrosoftCustomerAgreement" in (overall_agreement or ""))

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

    # 5) Blockers (only for non-transferable subs)
    blockers_rows: List[List[str]] = []
    for sub_id in non_transferable_subs:
        all_rgs = list_rgs(sub_id)
        grouped = list_resources_by_rg(sub_id)
        if not grouped:
            logging.info(f"Skipping blockers for {sub_id}: no resources.")
            continue
        for src_rg, ids in grouped.items():
            tgt_rg = pick_intrasub_target_rg(src_rg, all_rgs)
            if not tgt_rg:
                logging.info(f"Skipping RG '{src_rg}' in {sub_id}: no alternate target RG exists.")
                continue
            target_rg_id = f"/subscriptions/{sub_id}/resourceGroups/{tgt_rg}"

            # Optional validateMoveResources (can be skipped via --no-validate)
            if args.no_validate:
                result = {}
            else:
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
        print("🔎 Blockers scan: none detected (validateMoveResources + move-support table).")

if __name__ == "__main__":
    main()
