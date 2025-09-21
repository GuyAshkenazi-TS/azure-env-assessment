#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Stage 1: Fast subscription discovery (read-only)
Outputs:
  1) subscriptions_discovery_<ts>.csv  (Subscription ID, Offer, Owner, Transferable)
Also prints ready-to-copy commands for Stage 2 per subscription.
"""

import os, subprocess, json, csv, sys, logging, time
from datetime import datetime

os.environ.setdefault("AZURE_CORE_NO_COLOR", "1")
os.environ.setdefault("AZURE_EXTENSION_USE_DYNAMIC_INSTALL", "yes_without_prompt")

# --- CONFIG (can be overridden via env vars) ---
MOVE_SUPPORT_URL = os.getenv(
    "MOVE_SUPPORT_URL",
    "https://raw.githubusercontent.com/GuyAshkenazi-TS/azure-env-assessment/refs/heads/main/move-support-resources-local.csv"
)

STAGE2_RAW = os.getenv(
    "STAGE2_RAW",
    "https://raw.githubusercontent.com/GuyAshkenazi-TS/azure-env-assessment/refs/heads/main/azure_assess_stage2.py"
)

MISSING = "Not available"

def az(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()

def az_json(cmd, default):
    try:
        _, out, _ = az(cmd)
        return json.loads(out) if out else default
    except Exception:
        return default

def ensure_login():
    az(["az", "account", "show", "--only-show-errors"])

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

def transferable_to_ea(offer: str) -> str:
    return "Yes" if offer in ("EA","Pay-As-You-Go") else "No"

def banner(text: str):
    line = "─" * len(text)
    print(f"\n{text}\n{line}")

def main():
    start = time.perf_counter()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    logging.info("Stage-1: starting subscription discovery")

    ensure_login()

    subs = az_json(["az","account","list","--all","-o","json"], [])
    if not subs:
        logging.warning("No subscriptions found (or insufficient permissions).")
        print("No subscriptions found.")
        return

    logging.info(f"Found {len(subs)} subscriptions to process.")
    billing_accounts = az_json(["az","billing","account","list","-o","json"], [])
    overall_agreement = ""
    try:
        overall_agreement = (billing_accounts[0].get("agreementType") or "")
    except Exception:
        pass

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_discovery = f"subscriptions_discovery_{ts}.csv"
    headers = ["Subscription ID","Sub. Type","Sub. Owner","Transferable (Internal)"]
    rows=[]

    total = len(subs)
    for i, s in enumerate(subs, start=1):
        sub_id = s.get("id","")
        if not sub_id:
            logging.warning(f"Skipping entry {i}/{total}: missing subscription id.")
            continue

        logging.info(f"[{i}/{total}] Processing subscription: {sub_id}")

        arm = az_json(
            ["az","rest","--method","get","--url", f"https://management.azure.com/subscriptions/{sub_id}?api-version=2020-01-01","-o","json"],
            {}
        )
        has_err=("error" in arm)
        quota_id = arm.get("subscriptionPolicies",{}).get("quotaId","") if not has_err else ""
        auth_src = arm.get("authorizationSource","") if not has_err else ""
        bsub = az_json(["az","billing","subscription","show","--subscription-id",sub_id,"-o","json"], {})
        has_mca = bool(bsub.get("billingAccountId")) if bsub else ("MicrosoftCustomerAgreement" in overall_agreement)

        offer = offer_from_quota(quota_id, auth_src, has_mca)
        owner = resolve_owner(sub_id, offer)
        transferable = transferable_to_ea(offer)

        rows.append([sub_id, offer, owner, transferable])

    # Write CSV
    with open(out_discovery,"w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(headers); w.writerows(rows)

    elapsed = time.perf_counter() - start
    logging.info(f"Discovery complete in {elapsed:.1f}s. CSV written to: {out_discovery}")

    print(f"✅ Subscriptions CSV: {out_discovery}")

    banner("Run Stage-2 per subscription (copy & paste)")
    for sub_id, *_ in rows:
        cmd = (
            f'python3 <(curl -s "{STAGE2_RAW}") '
            f'--subscription "{sub_id}" '
            f'--move-support-url "{MOVE_SUPPORT_URL}"'
        )
        print(cmd)

    banner("Tip")
    print("You can run Stage-2 for multiple large subscriptions in parallel terminals.")

if __name__ == "__main__":
    main()
