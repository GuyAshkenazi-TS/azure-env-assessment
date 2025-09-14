#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Azure Migration Assessor – ONE SHOT, zero-setup (CSV only, read-only)
Step 1: map subscriptions -> who is transferable to EA, who isn't
  - azure_env_discovery_<ts>.csv   (EXACT columns like Script #1)
  - non_transferable_reasons_<ts>.csv  (only non-transferables + why)
Step 2: for all non-transferable subscriptions -> run blockers scan (validateMoveResources)
  - blockers_details_<ts>.csv  (resource-level blockers per RG/Subscription)

Read-only by default. No RG creation. If target RG doesn’t exist, we log and skip validation for that sub.
"""

import subprocess, json, argparse, csv, sys, logging, re
from datetime import datetime
from typing import Dict, Any, List, Tuple

MISSING = "Not available"

# ---------------------------
# Azure CLI helpers
# ---------------------------
def az(cmd: List[str], check: bool = True):
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
# Offer classification (aligns with your Script #1)
# ---------------------------
def offer_from_quota(quota_id: str, authorization_source: str, has_mca_billing_link: bool) -> str:
    q = quota_id or ""
    if any(x in q for x in ("MSDN", "MS-AZR-0029P", "MS-AZR-0062P", "MS-AZR-0063P", "VisualStudio", "VS")):
        return "MSDN"  # Dev/Test classic
    if q in ("PayAsYouGo_2014-09-01",) or any(x in q for x in ("MS-AZR-0003P","MS-AZR-0017P","MS-AZR-0023P")):
        return "Pay-As-You-Go"
    if any(x in q for x in ("MS-AZR-0145P","MS-AZR-0148P","MS-AZR-0033P","MS-AZR-0034P")):
        return "EA"
    if authorization_source == "ByPartner":
        return "CSP"
    if has_mca_billing_link:
        return "MCA-online"
    return MISSING

def transferable_to_ea(offer: str) -> str:
    # Same rule as Script #1: EA and Pay-As-You-Go => Yes, everything else => No
    return "Yes" if offer in ("EA","Pay-As-You-Go") else "No"

# ---------------------------
# Owner resolution (text guidance when we can’t read it)
# ---------------------------
def get_classic_account_admin_via_rest(sub_id: str) -> str:
    url = f"https://management.azure.com/subscriptions/{sub_id}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01"
    code, out, _ = az(["az","rest","--only-show-errors","--method","get","--url",url,"-o","json"], check=False)
    if code != 0 or not out:
        return ""
    try:
        js = json.loads(out)
        for item in js.get("value", []):
            if item.get("properties", {}).get("role") == "Account Administrator":
                email = item.get("properties", {}).get("emailAddress","")
                if email: return email
    except Exception:
        pass
    return ""

def mca_billing_owner_for_sub(sub_id: str) -> str:
    bsub = az_json(["az","billing","subscription","show","--subscription-id",sub_id,"-o","json"], {})
    ba = bsub.get("billingAccountId"); bp = bsub.get("billingProfileId"); inv = bsub.get("invoiceSectionId")
    scope = None
    if ba and bp and inv: scope = f"/providers/Microsoft.Billing/billingAccounts/{ba}/billingProfiles/{bp}/invoiceSections/{inv}"
    elif ba and bp:       scope = f"/providers/Microsoft.Billing/billingAccounts/{ba}/billingProfiles/{bp}"
    elif ba:              scope = f"/providers/Microsoft.Billing/billingAccounts/{ba}"
    if not scope: return ""
    roles = az_json(["az","billing","role-assignment","list","--scope",scope,"-o","json"], [])
    for r in roles:
        if (r.get("roleDefinitionName") or "") == "Owner":
            return r.get("principalEmail") or r.get("principalName") or r.get("signInName") or ""
    return ""

def resolve_owner(sub_id: str, offer: str) -> str:
    if offer in ("MSDN","Pay-As-You-Go","EA"):
        owner = get_classic_account_admin_via_rest(sub_id)
        if owner: return owner
        return "Check in EA portal - Account Owner" if offer=="EA" else "Check in Portal - classic subscription"
    if offer in ("MCA-online","MCA-E"):
        owner = mca_billing_owner_for_sub(sub_id)
        return owner if owner else "Check in Billing (MCA)"
    if offer == "CSP":
        return "Managed by partner - CSP"
    return MISSING

# ---------------------------
# Non-transferable reason matrix (CSV #2)
# ---------------------------
def reason_for_non_transferable(offer: str, state: str, auth_src: str) -> Tuple[str,str,str]:
    if state and state.lower()!="enabled":
        return ("DisabledSubscription", "Subscription state must be Active/Enabled before transfer.", "Move prerequisites; disabled subs can’t transfer")
    if offer == "CSP":
        return ("PartnerManagedNotDirectToEA", "CSP → EA isn’t an automatic billing transfer; requires manual resource move to EA-owned subscription.", "Use resource move guidance")
    if offer in ("MCA-online","MCA-E"):
        return ("ManualResourceMoveRequired", "MCA → EA direct billing transfer isn’t supported; move resources into EA subscription.", "Move resources to new subscription")
    if offer in ("MSDN", MISSING):
        return ("NotSupportedOffer", "Dev/Test or classic/unknown offer isn’t supported for a direct EA transfer.", "Offer/transfer matrix; use resource move if needed")
    return ("Unknown", "Insufficient data to determine blocking reason.", "Check tenant/offer/permissions")

# ---------------------------
# Blockers scan (validateMoveResources) for non-transferables
# ---------------------------
def list_resources_by_rg(source_subscription_id: str) -> Dict[str, List[str]]:
    cmd = ["az","resource","list","--subscription",source_subscription_id,"--query","[].{id:id, type:type, rg:resourceGroup}","-o","json"]
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
        if r.get("type") in non_movable_types:  # skip well-known non-movables
            continue
        rg = r.get("rg"); rid = r.get("id")
        if rg and rid:
            grouped.setdefault(rg, []).append(rid)
    return grouped

def validate_move_resources(source_subscription_id: str, rg: str, resource_ids: List[str], target_rg_id: str) -> Dict[str, Any]:
    body = json.dumps({"resources": resource_ids, "targetResourceGroup": target_rg_id})
    cmd = ["az","resource","invoke-action","--action","validateMoveResources",
           "--ids", f"/subscriptions/{source_subscription_id}/resourceGroups/{rg}",
           "--request-body", body]
    code, out, err = az(cmd, check=False)
    if code == 0 and out:
        try: return json.loads(out)
        except Exception: return {}
    return {"error":{"code":"ValidationFailed","message": err or "Validation failed"}}

def extract_blocker_from_error(err: Dict[str, Any]) -> Tuple[str,str,str]:
    msg = json.dumps(err, ensure_ascii=False).lower()
    if "requestdisallowedbypolicy" in msg or "policy" in msg:
        if "tag" in msg and "owner" in msg and "email" in msg:
            return ("PolicyBlocked", "Required 'owner' tag with valid email (may require specific domain).", "Align tags/policy; add owner tag and re-validate")
        return ("PolicyBlocked", "Blocked by Azure Policy on source/target RG or subscription.", "Align tags/policy; re-validate")
    if "lock" in msg or "readonly" in msg:
        return ("ResourceLockPresent", "Read-only lock on source or destination RG/subscription.", "Remove lock before move")
    if ("not registered for a resource type" in msg) or ("provider" in msg and "register" in msg):
        return ("ProviderRegistrationMissing", "Destination subscription missing required Resource Provider registration.", "Register provider in target sub")
    if "child" in msg and "parent" in msg:
        return ("CrossRGParentChildDependency", "Child resource must move with its parent (or vice versa).", "Move together / unify RG first")
    if "cannot be moved" in msg or "is not supported for move" in msg:
        return ("UnsupportedResourceType", "Resource type/SKU isn’t supported for cross-subscription move.", "See move-support table")
    if "authorization" in msg or "not permitted" in msg or "insufficient privileges" in msg:
        return ("InsufficientPermissions", "Caller lacks required move/write permissions on source/destination.", "Need moveResources on source RG; write on target RG")
    return ("ValidationFailed", "Azure returned a validation failure. Inspect details JSON.", "See ARM move guidance")

def target_rg_exists(sub_id: str, rg: str) -> bool:
    code, _, _ = az(["az","group","show","--subscription",sub_id,"--name",rg], check=False)
    return code == 0

# ---------------------------
# Main
# ---------------------------
def main():
    ap = argparse.ArgumentParser(description="End-to-end EA transfer assessor (auto blockers scan for non-transferables).")
    ap.add_argument("--ea-target-sub", help="EA Subscription ID used as validation target for resource moves (blockers).")
    ap.add_argument("--ea-target-rg", help="Target Resource Group name in the EA subscription (MUST exist; no creation).")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    ensure_login()

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

    # CSV #1: EXACT like Script #1
    headers1 = ["Subscription ID","Sub. Type","Sub. Owner","Transferable (Internal)"]
    rows1 = []
    # CSV #2: reasons
    headers2 = ["Subscription ID","Sub. Type","ReasonCode","Why","DocRef"]
    rows2 = []
    # CSV #3: blockers
    headers_blk = ["SubscriptionId","ResourceGroup","ResourceId","BlockerCategory","Why","DocRef"]
    blockers_rows = []

    # Pre-check: target for blockers (we can prompt later if missing)
    target_sub = args.ea_target_sub
    target_rg  = args.ea_target_rg

    # Collect non-transferables to scan later
    non_transferable_subs: List[Tuple[str,str]] = []  # (sub_id, offer)

    for s in subs:
        sub_id = s.get("id","")
        state  = s.get("state","")
        arm = az_json(["az","rest","--method","get","--url", f"https://management.azure.com/subscriptions/{sub_id}?api-version=2020-01-01","-o","json"], {})
        has_error = ("error" in arm)
        quota_id = arm.get("subscriptionPolicies",{}).get("quotaId","") if not has_error else ""
        auth_src = arm.get("authorizationSource","") if not has_error else ""
        bsub = az_json(["az","billing","subscription","show","--subscription-id",sub_id,"-o","json"], {})
        has_mca_link = bool(bsub.get("billingAccountId"))

        offer = offer_from_quota(quota_id, auth_src, has_mca_link if not has_error else (overall_agreement.find("MicrosoftCustomerAgreement")>=0))
        owner = resolve_owner(sub_id, offer)
        transferable = transferable_to_ea(offer)

        rows1.append([sub_id, offer, owner, transferable])
        if transferable == "No":
            code, why, doc = reason_for_non_transferable(offer, state, auth_src)
            rows2.append({"Subscription ID": sub_id, "Sub. Type": offer, "ReasonCode": code, "Why": why, "DocRef": doc})
            non_transferable_subs.append((sub_id, offer))

    # Write CSV #1 + #2
    with open(out_discovery, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(headers1); w.writerows(rows1)
    with open(out_reasons, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers2); w.writeheader(); [w.writerow(r) for r in rows2]

    print(f"✅ Discovery CSV: {out_discovery}")
    print(f"✅ Reasons   CSV: {out_reasons}")

    # If there are non-transferables, run blockers scan (validateMoveResources)
    if non_transferable_subs:
        # Ensure we have a target pair; if not supplied, prompt once.
        if not target_sub:
            try:
                target_sub = input("Enter EA target Subscription ID for blockers validation (or leave blank to skip blockers): ").strip()
            except EOFError:
                target_sub = ""
        if target_sub and not target_rg:
            try:
                target_rg = input("Enter EA target Resource Group name (must already exist): ").strip()
            except EOFError:
                target_rg = ""

        if target_sub and target_rg:
            if not target_rg_exists(target_sub, target_rg):
                print(f"⚠️  Target RG '{target_rg}' not found in subscription '{target_sub}'. Skipping blockers validation (read-only, no creation).")
            else:
                target_rg_id = f"/subscriptions/{target_sub}/resourceGroups/{target_rg}"
                for sub_id, offer in non_transferable_subs:
                    logging.info(f"Scanning blockers for non-transferable subscription {sub_id} ({offer}) → target {target_rg_id}")
                    grouped = list_resources_by_rg(sub_id)
                    for rg, ids in grouped.items():
                        result = validate_move_resources(sub_id, rg, ids, target_rg_id)
                        if isinstance(result, dict) and "error" in result:
                            cat, why, doc = extract_blocker_from_error(result["error"])
                            for rid in ids:
                                blockers_rows.append([sub_id, rg, rid, cat, why, doc])
                        # success → no blockers row (resources assumed movable)
                if blockers_rows:
                    with open(out_blockers, "w", newline="", encoding="utf-8") as f:
                        w = csv.writer(f); w.writerow(headers_blk); w.writerows(blockers_rows)
                    print(f"🔎 Blockers CSV:  {out_blockers}")
                else:
                    print("🔎 Blockers scan: no blockers detected by validateMoveResources.")
        else:
            print("ℹ️  No EA target provided. Blockers validation skipped (Discovery/Reasons already generated).")

if __name__ == "__main__":
    main()
