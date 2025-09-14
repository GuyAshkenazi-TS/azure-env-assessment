#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Azure Migration Assessor - NO 3rd-party deps (CSV only)
Outputs:
  1) azure_env_discovery_<timestamp>.csv
     Columns (EXACT like Script #1): ["Subscription ID","Sub. Type","Sub. Owner","Transferable (Internal)"]
  2) non_transferable_reasons_<timestamp>.csv
     Columns: ["Subscription ID","Sub. Type","ReasonCode","Why","DocRef"]
Optional (with --deep-scan):
  3) blockers_details_<timestamp>.csv
     Columns: ["SubscriptionId","ResourceGroup","ResourceId","BlockerCategory","Why","DocRef"]
"""

import subprocess, json, argparse, csv, sys, logging, re
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

MISSING = "Not available"

# ---------------------------
# Azure CLI helpers
# ---------------------------
def az(cmd: List[str], check: bool = True) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise subprocess.CalledProcessError(p.returncode, cmd, p.stdout, p.stderr)
    return p.returncode, p.stdout.strip(), p.stderr.strip()

def az_json(cmd: List[str], default: Any):
    try:
        _, out, _ = az(cmd)
        return json.loads(out) if out else default
    except Exception:
        return default

def ensure_login():
    try:
        az(["az", "account", "show", "--only-show-errors"], check=True)
    except Exception:
        az(["az", "login", "--only-show-errors", "-o", "none"], check=False)

# ---------------------------
# Offer classification
# ---------------------------
def offer_from_quota(quota_id: str, authorization_source: str, has_mca_billing_link: bool) -> str:
    q = quota_id or ""
    # MSDN / Visual Studio (Dev/Test classic)
    if any(x in q for x in ("MSDN", "MS-AZR-0029P", "MS-AZR-0062P", "MS-AZR-0063P", "VisualStudio", "VS")):
        return "MSDN"
    # Pay-As-You-Go (MOSP)
    if q in ("PayAsYouGo_2014-09-01",) or any(x in q for x in ("MS-AZR-0003P", "MS-AZR-0017P", "MS-AZR-0023P")):
        return "Pay-As-You-Go"
    # EA (כולל Dev/Test של EA)
    if any(x in q for x in ("MS-AZR-0145P", "MS-AZR-0148P", "MS-AZR-0033P", "MS-AZR-0034P")):
        return "EA"
    # CSP ע"י שותף
    if authorization_source == "ByPartner":
        return "CSP"
    # MCA (רמז דרך billing link)
    if has_mca_billing_link:
        return "MCA-online"
    return MISSING

def transferable_to_ea(offer: str) -> str:
    # שמרתי לוגיקה זהה לסקריפט 1: EA ו-Pay-As-You-Go = Yes; כל השאר = No
    return "Yes" if offer in ("EA", "Pay-As-You-Go") else "No"

# ---------------------------
# Owner resolution (טקסט הנחיה אם לא ניתן למשוך)
# ---------------------------
def get_classic_account_admin_via_rest(sub_id: str) -> str:
    url = f"https://management.azure.com/subscriptions/{sub_id}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01"
    code, out, err = az(["az", "rest", "--only-show-errors", "--method", "get", "--url", url, "-o", "json"], check=False)
    if code != 0 or not out:
        return ""
    try:
        js = json.loads(out)
        for item in js.get("value", []):
            if item.get("properties", {}).get("role") == "Account Administrator":
                email = item.get("properties", {}).get("emailAddress", "")
                if email:
                    return email
    except Exception:
        pass
    return ""

def mca_billing_owner_for_sub(sub_id: str) -> str:
    bsub = az_json(["az", "billing", "subscription", "show", "--subscription-id", sub_id, "-o", "json"], {})
    ba = bsub.get("billingAccountId")
    bp = bsub.get("billingProfileId")
    inv = bsub.get("invoiceSectionId")
    scope = None
    if ba and bp and inv:
        scope = f"/providers/Microsoft.Billing/billingAccounts/{ba}/billingProfiles/{bp}/invoiceSections/{inv}"
    elif ba and bp:
        scope = f"/providers/Microsoft.Billing/billingAccounts/{ba}/billingProfiles/{bp}"
    elif ba:
        scope = f"/providers/Microsoft.Billing/billingAccounts/{ba}"
    if not scope:
        return ""
    roles = az_json(["az", "billing", "role-assignment", "list", "--scope", scope, "-o", "json"], [])
    for r in roles:
        if (r.get("roleDefinitionName") or "") == "Owner":
            return r.get("principalEmail") or r.get("principalName") or r.get("signInName") or ""
    return ""

def owner_guidance_for_offer(offer: str) -> str:
    if offer in ("MSDN", "Pay-As-You-Go"):
        return "Check in Portal - classic subscription"
    if offer == "EA":
        return "Check in EA portal - Account Owner"
    if offer in ("MCA-online", "MCA-E"):
        return "Check in Billing (MCA)"
    if offer == "CSP":
        return "Managed by partner - CSP"
    return MISSING

def resolve_owner(sub_id: str, offer: str) -> str:
    if offer in ("MSDN", "Pay-As-You-Go", "EA"):
        owner = get_classic_account_admin_via_rest(sub_id)
        if owner:
            return owner
        return "Check in EA portal - Account Owner" if offer == "EA" else "Check in Portal - classic subscription"
    if offer in ("MCA-online", "MCA-E"):
        owner = mca_billing_owner_for_sub(sub_id)
        return owner if owner else "Check in Billing (MCA)"
    if offer == "CSP":
        return "Managed by partner - CSP"
    return owner_guidance_for_offer(offer)

# ---------------------------
# Reasons (CSV #2)
# ---------------------------
def reason_for_non_transferable(offer: str, state: str, auth_src: str) -> Tuple[str, str, str]:
    if state and state.lower() != "enabled":
        return ("DisabledSubscription", "Subscription state must be Active/Enabled before transfer.", "Move prerequisites; disabled subs can’t transfer")
    if offer == "CSP":
        return ("PartnerManagedNotDirectToEA", "CSP → EA isn’t an automatic billing transfer; requires manual resource move to EA-owned subscription.", "Use resource move guidance")
    if offer in ("MCA-online", "MCA-E"):
        return ("ManualResourceMoveRequired", "MCA → EA direct billing transfer isn’t supported; move resources into EA subscription.", "Move resources to new subscription")
    if offer in ("MSDN", MISSING):
        return ("NotSupportedOffer", "Dev/Test or classic/unknown offer isn’t supported for a direct EA transfer.", "Offer/transfer matrix; use resource move if needed")
    return ("Unknown", "Insufficient data to determine blocking reason.", "Check tenant/offer/permissions")

# ---------------------------
# Deep scan (optional)
# ---------------------------
def get_all_resources(source_subscription_id: str) -> Dict[str, List[str]]:
    cmd = ["az", "resource", "list", "--subscription", source_subscription_id, "--query", "[].{id:id, type:type, rg:resourceGroup}", "-o", "json"]
    resources = az_json(cmd, [])
    non_movable_types = {
        "Microsoft.Network/networkWatchers",
        "Microsoft.OffAzure/VMwareSites",
        "Microsoft.OffAzure/MasterSites",
        "Microsoft.Migrate/migrateprojects",
        "Microsoft.Migrate/assessmentProjects",
    }
    grouped = {}
    for r in resources:
        if r.get("type") in non_movable_types:
            continue
        rg = r.get("rg")
        rid = r.get("id")
        if rg and rid:
            grouped.setdefault(rg, []).append(rid)
    return grouped

def validate_move_resources(source_subscription_id: str, resource_group: str, resource_ids: List[str], target_rg_id: str) -> Dict[str, Any]:
    body = json.dumps({"resources": resource_ids, "targetResourceGroup": target_rg_id})
    cmd = [
        "az","resource","invoke-action","--action","validateMoveResources",
        "--ids", f"/subscriptions/{source_subscription_id}/resourceGroups/{resource_group}",
        "--request-body", body
    ]
    code, out, err = az(cmd, check=False)
    if code == 0 and out:
        try:
            return json.loads(out)
        except Exception:
            return {}
    return {"error":{"code":"ValidationFailed","message": err or "Validation failed"}}

def extract_blocker_from_error(err: Dict[str, Any]) -> Tuple[str, str, str]:
    msg = json.dumps(err, ensure_ascii=False).lower()
    if "requestdisallowedbypolicy" in msg or "policy" in msg:
        if "tag" in msg and "owner" in msg and "email" in msg:
            return ("PolicyBlocked", "Required 'owner' tag with valid email (may require specific domain).", "Add owner tag; re-validate")
        return ("PolicyBlocked", "Blocked by Azure Policy on source/target RG or subscription.", "Align tags/policy; re-validate")
    if "lock" in msg or "readonly" in msg:
        return ("ResourceLockPresent", "Read-only lock on source or destination RG/subscription.", "Remove lock before move")
    if ("isn’t registered for a resource type" in msg) or ("not registered for a resource type" in msg) or ("provider" in msg and "register" in msg):
        return ("ProviderRegistrationMissing", "Destination subscription not registered for required Resource Provider.", "Register provider then retry")
    if "child" in msg and "parent" in msg:
        return ("CrossRGParentChildDependency", "Child resource must move with its parent (or vice versa).", "Move together / unify RG")
    if "cannot be moved" in msg or "is not supported for move" in msg:
        return ("UnsupportedResourceType", "Resource type/SKU isn’t supported for move across subscriptions.", "See move-support table")
    if "authorization" in msg or "not permitted" in msg or "insufficient privileges" in msg:
        return ("InsufficientPermissions", "Caller lacks required move/write permissions on source/destination.", "Need moveResources on source RG; write on target RG")
    return ("ValidationFailed", "Azure returned a validation failure. Inspect details JSON.", "See ARM move guidance")

# ---------------------------
# Main
# ---------------------------
def main():
    ap = argparse.ArgumentParser(description="Assess Azure subscriptions for EA transfer eligibility (CSV only, zero setup).")
    ap.add_argument("--deep-scan", action="store_true", help="Add per-resource blockers CSV for a specific source/target pair.")
    ap.add_argument("--source-sub", help="Source subscription ID (for deep scan)")
    ap.add_argument("--target-sub", help="Target subscription ID (for deep scan)")
    ap.add_argument("--target-rg", help="Target RG name (for deep scan)")
    ap.add_argument("--location", help="Target RG region (for deep scan)")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    ensure_login()

    subs = az_json(["az","account","list","--all","-o","json"], [])
    # Hint for MCA overall (in case ARM query is forbidden)
    billing_accounts = az_json(["az","billing","account","list","-o","json"], [])
    overall_agreement = ""
    try:
        overall_agreement = (billing_accounts[0].get("agreementType") or "")
    except Exception:
        pass

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out1 = f"azure_env_discovery_{ts}.csv"
    out2 = f"non_transferable_reasons_{ts}.csv"

    headers1 = ["Subscription ID","Sub. Type","Sub. Owner","Transferable (Internal)"]
    rows1 = []
    rows2 = []

    for s in subs:
        sub_id = s.get("id","")
        state  = s.get("state","")
        # ARM subscription for quotaId/authorizationSource
        arm = az_json(["az","rest","--method","get","--url", f"https://management.azure.com/subscriptions/{sub_id}?api-version=2020-01-01","-o","json"], {})
        has_error = ("error" in arm)
        quota_id = arm.get("subscriptionPolicies",{}).get("quotaId","") if not has_error else ""
        auth_src = arm.get("authorizationSource","") if not has_error else ""

        # billing link hint for MCA
        bsub = az_json(["az","billing","subscription","show","--subscription-id", sub_id, "-o","json"], {})
        has_mca_link = bool(bsub.get("billingAccountId"))

        offer = offer_from_quota(quota_id, auth_src, has_mca_link if not has_error else (overall_agreement.find("MicrosoftCustomerAgreement")>=0))
        owner = resolve_owner(sub_id, offer)
        transferable = transferable_to_ea(offer)

        rows1.append([sub_id, offer, owner, transferable])

        if transferable == "No":
            code, why, doc = reason_for_non_transferable(offer, state, auth_src)
            rows2.append({"Subscription ID": sub_id, "Sub. Type": offer, "ReasonCode": code, "Why": why, "DocRef": doc})

    # Write CSV #1
    with open(out1, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(headers1); w.writerows(rows1)
    # Write CSV #2
    headers2 = ["Subscription ID","Sub. Type","ReasonCode","Why","DocRef"]
    with open(out2, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers2); w.writeheader(); [w.writerow(r) for r in rows2]

    print(f"✅ CSV #1 (like Script #1): {out1}")
    print(f"✅ CSV #2 (reasons):         {out2}")

    # Optional deep scan (single source/target pair) → blockers_details_<ts>.csv
    if args.deep_scan:
        for req in ("source-sub","target-sub","target-rg","location"):
            if not getattr(args, req.replace("-","_")):
                print(f"Skipping deep scan: missing --{req}")
                return
        # Ensure/try target RG exists (best-effort; ללא תלות חיצונית)
        code, _, _ = az(["az","group","show","--name", args.target_rg, "--subscription", args.target_sub], check=False)
        if code != 0:
            az(["az","group","create","--name", args.target_rg, "--location", args.location, "--subscription", args.target_sub], check=False)

        target_rg_id = f"/subscriptions/{args.target_sub}/resourceGroups/{args.target_rg}"
        grouped = get_all_resources(args.source_sub)
        blockers_csv = f"blockers_details_{ts}.csv"
        headers_blk = ["SubscriptionId","ResourceGroup","ResourceId","BlockerCategory","Why","DocRef"]

        with open(blockers_csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f); w.writerow(headers_blk)
            for rg, ids in grouped.items():
                result = validate_move_resources(args.source_sub, rg, ids, target_rg_id)
                if isinstance(result, dict) and "error" in result:
                    cat, why, doc = extract_blocker_from_error(result["error"])
                    for rid in ids:
                        w.writerow([args.source_sub, rg, rid, cat, why, doc])
                # success → no blockers to record

        print(f"🔎 Deep-scan blockers CSV: {blockers_csv}")

if __name__ == "__main__":
    main()
