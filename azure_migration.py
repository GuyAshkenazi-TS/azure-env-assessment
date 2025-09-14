python3 - <<'PY'
# -*- coding: utf-8 -*-
# Azure Migration Assessor – unified, auto, read-only
# CSVs:
# 1) azure_env_discovery_<ts>.csv         -> Subscription ID, Sub. Type, Sub. Owner, Transferable (Internal)
# 2) non_transferable_reasons_<ts>.csv    -> non-transferables + why
# 3) blockers_details_<ts>.csv            -> resource-level blockers (validateMoveResources + move-support table)

import os, subprocess, json, csv, re, urllib.request
from datetime import datetime
from typing import Dict, Any, List, Tuple

# --- env (no prompts, dynamic install if needed) ---
os.environ.setdefault("AZURE_CORE_NO_COLOR", "1")
os.environ.setdefault("AZURE_EXTENSION_USE_DYNAMIC_INSTALL", "yes_without_prompt")

MISSING = "Not available"
MOVE_SUPPORT_CSV = "https://raw.githubusercontent.com/tfitzmac/resource-capabilities/master/move-support-resources.csv"

# ------------- AZ helpers -------------
def az(cmd: List[str], check: bool = True):
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

# ------------- Offer / Owner / Transferability -------------
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

def reason_for_non_transferable(offer: str, state: str, auth_src: str):
    if state and state.lower() != "enabled":
        return ("DisabledSubscription","Subscription must be Active/Enabled before transfer.","Move prerequisites")
    if offer == "CSP":
        return ("PartnerManagedNotDirectToEA","CSP → EA isn’t an automatic billing transfer; requires manual resource move.","Move resources guidance")
    if offer in ("MCA-online","MCA-E"):
        return ("ManualResourceMoveRequired","MCA → EA direct billing transfer isn’t supported; move resources into EA subscription.","Move resources guidance")
    if offer in ("MSDN", MISSING):
        return ("NotSupportedOffer","Dev/Test or classic/unknown offer isn’t supported for a direct EA transfer.","Transfer matrix")
    return ("Unknown","Insufficient data to determine blocking reason.","Check tenant/offer/permissions")

# ------------- Inventory & validation (read-only) -------------
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

# ------------- move-support table + Parent/Child -------------
def load_move_support_map() -> Dict[str,bool]:
    support = {}
    with urllib.request.urlopen(MOVE_SUPPORT_CSV) as resp:
        lines = resp.read().decode("utf-8").splitlines()
    rdr = csv.DictReader(lines)
    for row in rdr:
        key = f"{(row.get('resourceProvider') or '').strip()}/{(row.get('resourceType') or '').strip()}".lower()
        support[key] = ((row.get("subscription") or "").strip().lower() == "yes")
    return support

def parse_types(resource_id: str):
    m = re.search(r"/providers/([^/]+)/([^/]+)(/.*)?", resource_id, re.IGNORECASE)
    if not m:
        return False, None, None, None
    ns, first_type, rest = m.group(1), m.group(2), m.group(3) or ""
    top_type = f"{ns}/{first_type}"
    path = (rest or "").strip("/")
    is_child=False; parent_id=None; parent_type=top_type
    if path:
        segs = path.split("/")
        if len(segs)>=3:
            is_child=True
            parent_id = re.sub(r"(/providers/[^/]+/[^/]+/[^/]+).*", r"\\1", resource_id, flags=re.IGNORECASE)
            # (parent_type already = top_type)
    return is_child, top_type, parent_id, parent_type

def classify_with_table(resource_id: str, details_msg: str, support_map: dict) -> Dict[str,Any]:
    is_child, top_type, parent_id, parent_type = parse_types(resource_id)
    top_key = (top_type or "").lower()
    top_supported = support_map.get(top_key, None)

    dm = (details_msg or "").lower()
    if "requestdisallowedbypolicy" in dm:
        return {"BlockerCategory":"PolicyBlocked","Why":"Blocked by Azure Policy/required tag","DocRef":"move-support",
                "ResourceTypeTopLevel": top_type or "", "IsChild":"Yes" if is_child else "No",
                "ParentId": parent_id or "", "ParentType": parent_type or "", "ParentSupported": ""}

    if "authorizationfailed" in dm or "denyassignmentauthorizationfailed" in dm:
        return {"BlockerCategory":"InsufficientPermissions","Why":"Caller lacks required RBAC to validate/move","DocRef":"move-support",
                "ResourceTypeTopLevel": top_type or "", "IsChild":"Yes" if is_child else "No",
                "ParentId": parent_id or "", "ParentType": parent_type or "", "ParentSupported": ""}

    if "is not registered for" in dm and "provider" in dm:
        return {"BlockerCategory":"ProviderRegistrationMissing","Why":"Target subscription missing resource provider registration","DocRef":"move-support",
                "ResourceTypeTopLevel": top_type or "", "IsChild":"Yes" if is_child else "No",
                "ParentId": parent_id or "", "ParentType": parent_type or "", "ParentSupported": ""}

    # child/parent rules
    if is_child:
        if top_supported is False:
            return {"BlockerCategory":"ParentNotSupported","Why":"Parent type doesn’t support subscription move; unifying won’t help",
                    "DocRef":"move-support","ResourceTypeTopLevel": top_type or "","IsChild":"Yes",
                    "ParentId": parent_id or "", "ParentType": parent_type or "", "ParentSupported":"No"}
        else:
            return {"BlockerCategory":"ChildResourceMustMoveWithParent","Why":"Child can’t move alone; move the parent (top-level) resource",
                    "DocRef":"move-support","ResourceTypeTopLevel": top_type or "","IsChild":"Yes",
                    "ParentId": parent_id or "", "ParentType": parent_type or "", "ParentSupported": "Yes" if top_supported else "Unknown"}

    if top_supported is False:
        return {"BlockerCategory":"UnsupportedResourceType","Why":"Resource type doesn’t support subscription move",
                "DocRef":"move-support","ResourceTypeTopLevel": top_type or "","IsChild":"No",
                "ParentId":"", "ParentType":"", "ParentSupported":"No"}
    if top_supported is True:
        return {"BlockerCategory":"None","Why":"Supported for subscription move",
                "DocRef":"move-support","ResourceTypeTopLevel": top_type or "","IsChild":"No",
                "ParentId":"", "ParentType":"", "ParentSupported":"Yes"}
    return {"BlockerCategory":"Unknown","Why":"Resource type not found in move-support table",
            "DocRef":"move-support","ResourceTypeTopLevel": top_type or "","IsChild":"No",
            "ParentId":"", "ParentType":"", "ParentSupported":""}

# ------------- generic error → blocker (fallback) -------------
def extract_blocker_from_error(err: Dict[str,Any]) -> Tuple[str,str,str]:
    m = json.dumps(err, ensure_ascii=False).lower()
    if "requestdisallowedbypolicy" in m or "policy" in m:
        if "tag" in m and "owner" in m and "email" in m:
            return ("PolicyBlocked","Required 'owner' tag with valid email (may require specific domain).","Align tags/policy and re-validate")
        return ("PolicyBlocked","Blocked by Azure Policy on source/target RG or subscription.","Align policy and re-validate")
    if "lock" in m or "readonly" in m:
        return ("ResourceLockPresent","Read-only lock on source or destination RG/subscription.","Remove lock before move")
    if ("not registered for a resource type" in m) or ("provider" in m and "register" in m):
        return ("ProviderRegistrationMissing","Destination subscription missing required Resource Provider registration.","Register provider in target sub")
    if "child" in m and "parent" in m:
        return ("CrossRGParentChildDependency","Child resource must move with its parent (or vice versa).","Move together / unify RG first")
    if "cannot be moved" in m or "is not supported for move" in m:
        return ("UnsupportedResourceType","Resource type/SKU isn’t supported for move.","See move-support table")
    if "authorization" in m or "not permitted" in m or "insufficient privileges" in m:
        return ("InsufficientPermissions","Caller lacks required permissions on source/destination.","Ensure moveResources on source RG + write on target RG")
    return ("ValidationFailed","Azure returned a validation failure. Inspect details JSON.","See ARM move guidance")

# ------------- main -------------
def main():
    ensure_login()

    # discovery CSV (exact column names like Script #1)
    headers_discovery = ["Subscription ID","Sub. Type","Sub. Owner","Transferable (Internal)"]
    headers_reasons   = ["Subscription ID","Sub. Type","ReasonCode","Why","DocRef"]
    headers_blockers  = ["SubscriptionId","ResourceGroup","ResourceId","ResourceTypeTopLevel","IsChild","ParentId","ParentType","ParentSupported","BlockerCategory","Why","DocRef"]

    subs = az_json(["az","account","list","--all","-o","json"], [])
    billing_accounts = az_json(["az","billing","account","list","-o","json"], [])
    overall_agreement = ""
    try: overall_agreement = (billing_accounts[0].get("agreementType") or "")
    except Exception: pass

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_discovery = f"azure_env_discovery_{ts}.csv"
    out_reasons   = f"non_transferable_reasons_{ts}.csv"
    out_blockers  = f"blockers_details_{ts}.csv"

    rows_discovery=[]; rows_reasons=[]; non_transferables=[]
    # ---- Stage 1: discovery
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
            non_transferables.append(sub_id)

    with open(out_discovery,"w",newline="",encoding="utf-8") as f:
        csv.writer(f).writerows([headers_discovery, *rows_discovery])
    with open(out_reasons,"w",newline="",encoding="utf-8") as f:
        csv.writer(f).writerows([headers_reasons, *rows_reasons])

    print(f"✅ Discovery CSV: {out_discovery}")
    print(f"✅ Reasons   CSV: {out_reasons}")

    # ---- Stage 2: blockers for non-transferables (no EA required; intra-sub RG->RG)
    # move-support table (best-effort)
    try:
        support_map = load_move_support_map()
    except Exception:
        support_map = {}

    blockers_rows=[]
    for sub_id in non_transferables:
        all_rgs = list_rgs(sub_id)
        if not all_rgs:
            print(f"[INFO] Skipping blockers for {sub_id}: no resource groups found.")
            continue

        grouped = list_resources_by_rg(sub_id)
        if not grouped:
            print(f"[INFO] Skipping blockers for {sub_id}: no resources found.")
            continue

        for src_rg, ids in grouped.items():
            tgt_rg = pick_intrasub_target_rg(sub_id, src_rg, all_rgs)
            if not tgt_rg:
                print(f"[INFO] Skipping RG '{src_rg}' in {sub_id}: no alternate target RG exists in this subscription.")
                continue
            target_rg_id = f"/subscriptions/{sub_id}/resourceGroups/{tgt_rg}"

            result = validate_move_resources(sub_id, src_rg, ids, target_rg_id)

            if isinstance(result, dict) and "error" in result:
                err_msg = json.dumps(result["error"], ensure_ascii=False)
                # קודם כל מיפוי ע"פ ההודעה (למשל ResourceNotTopLevel) ואז cross-check עם טבלת התמיכה:
                for rid in ids:
                    cls = classify_with_table(rid, err_msg, support_map)
                    if cls.get("BlockerCategory") != "None":
                        blockers_rows.append([
                            sub_id, src_rg, rid,
                            cls.get("ResourceTypeTopLevel",""),
                            cls.get("IsChild","No"),
                            cls.get("ParentId",""),
                            cls.get("ParentType",""),
                            cls.get("ParentSupported",""),
                            cls.get("BlockerCategory","Unknown"),
                            cls.get("Why",""),
                            cls.get("DocRef","move-support")
                        ])
            else:
                # אם אין error כללי – עדיין מתייגים ילדים שאסור להזיז לבד וכו'
                for rid in ids:
                    cls = classify_with_table(rid, "", support_map)
                    if cls.get("BlockerCategory") not in ("None",):
                        blockers_rows.append([
                            sub_id, src_rg, rid,
                            cls.get("ResourceTypeTopLevel",""),
                            cls.get("IsChild","No"),
                            cls.get("ParentId",""),
                            cls.get("ParentType",""),
                            cls.get("ParentSupported",""),
                            cls.get("BlockerCategory","Unknown"),
                            cls.get("Why",""),
                            cls.get("DocRef","move-support")
                        ])

    if blockers_rows:
        with open(out_blockers,"w",newline="",encoding="utf-8") as f:
            csv.writer(f).writerows([headers_blockers, *blockers_rows])
        print(f"🔎 Blockers CSV: {out_blockers}")
    else:
        print("🔎 Blockers scan: no blockers detected by validateMoveResources (intra-sub) + move-support table.")

if __name__ == "__main__":
    main()
PY
