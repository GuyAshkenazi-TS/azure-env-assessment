#!/usr/bin/env bash
# Azure Properties -> CSV (safe & read-only)
# Columns: Subscription ID, Sub. Type (OFFER), Sub. Owner, Transferable (Internal)
# READ-ONLY: no writes/changes.

set -euo pipefail
export AZURE_EXTENSION_USE_DYNAMIC_INSTALL=yes_without_prompt
export AZURE_CORE_NO_COLOR=1

MISSING="Not available"

echo "== Azure Properties to CSV =="
# Login if needed (no-op in Cloud Shell unless switching accounts)
az account show --only-show-errors >/dev/null 2>&1 || az login --only-show-errors -o none || true

# Ensure billing extension (for MCA owner lookup)
az extension show --name billing --only-show-errors >/dev/null 2>&1 || az extension add --name billing -y --only-show-errors >/dev/null 2>&1 || true

TS=$(date +%Y%m%d_%H%M%S)
OUT_CSV="azure_env_discovery_${TS}.csv"
echo "Subscription ID,Sub. Type,Sub. Owner,Transferable (Internal)" > "$OUT_CSV"

# Cache overall agreement (used ONLY as a final fallback for MCA)
BILLING_JSON="$(az billing account list --only-show-errors -o json 2>/dev/null || echo "[]")"
OVERALL_AGR="$(jq -r '.[0].agreementType // empty' <<< "$BILLING_JSON" 2>/dev/null || echo "")"

# ---------- Helpers ----------

# Classify offer/type primarily from quotaId (matches Portal semantics)
offer_from_quota() {
  local quota="${1:-}"

  # MSDN / Visual Studio (classic)
  case "$quota" in
    *MSDN*|*MSDN_*|*VisualStudio*|*VS*|*MS-AZR-0029P*|*MS-AZR-0062P*|*MS-AZR-0063P*)
      echo "MSDN"; return;;
  esac

  # PAYG (MOSP classic) - includes PayAsYouGo_2014-09-01 and common PAYG codes
  case "$quota" in
    PayAsYouGo_2014-09-01|*MS-AZR-0003P*|*MS-AZR-0017P*|*MS-AZR-0023P*)
      echo "Pay-As-You-Go"; return;;
  esac

  # EA (incl. Dev/Test)
  case "$quota" in
    *MS-AZR-0145P*|*MS-AZR-0148P*|*MS-AZR-0033P*|*MS-AZR-0034P*)
      echo "EA"; return;;
  esac

  echo ""
}

# Transferability matrix (internal): Yes only for EA and PAYG
transferable_to_ea() {
  local offer="${1:-$MISSING}"
  case "$offer" in
    EA|Pay-As-You-Go) echo "Yes";;
    *) echo "No";;
  esac
}

# Try to fetch Billing Owner (MCA) if caller has Billing Reader on the scope
mca_billing_owner_for_sub() {
  local sub_id="${1:-}"
  local bsub ba bp is scope
  bsub="$(az billing subscription show --subscription-id "$sub_id" -o json 2>/dev/null || echo "{}")"
  ba="$(jq -r '.billingAccountId // empty' <<< "$bsub")"
  bp="$(jq -r '.billingProfileId // empty' <<< "$bsub")"
  is="$(jq -r '.invoiceSectionId // empty' <<< "$bsub")"

  if [[ -n "$ba" && -n "$bp" && -n "$is" ]]; then
    scope="/providers/Microsoft.Billing/billingAccounts/${ba}/billingProfiles/${bp}/invoiceSections/${is}"
  elif [[ -n "$ba" && -n "$bp" ]]; then
    scope="/providers/Microsoft.Billing/billingAccounts/${ba}/billingProfiles/${bp}"
  elif [[ -n "$ba" ]]; then
    scope="/providers/Microsoft.Billing/billingAccounts/${ba}"
  else
    echo ""; return
  fi

  az billing role-assignment list --scope "$scope" -o json 2>/dev/null \
    | jq -r '.[] | select((.roleDefinitionName // "")=="Owner")
              | (.principalEmail // .principalName // .signInName // empty)' \
    | head -n1
}

# Fetch Classic Account Administrator email via official REST (works without CLI flag)
get_classic_account_admin_via_rest() {
  local sub_id="${1:-}"
  local url="https://management.azure.com/subscriptions/${sub_id}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01"
  local resp
  resp="$(az rest --only-show-errors --method get --url "$url" -o json 2>/dev/null || echo '{}')"
  jq -r '.value[]? | select(.properties.role == "Account Administrator") | .properties.emailAddress // empty' <<< "$resp" | head -n1
}

# Owner guidance text by type (when actual email isn't retrievable)
owner_guidance_for_offer() {
  local offer="${1:-$MISSING}"
  case "$offer" in
    MSDN|Pay-As-You-Go) echo "Check in Portal - classic subscription";;
    EA)                  echo "Check in EA portal - Account Owner";;
    MCA-online|MCA-E)    echo "Check in Billing (MCA)";;
    CSP)                 echo "Managed by partner - CSP";;
    *)                   echo "$MISSING";;
  esac
}

# ---------- Main ----------

SUBS="$(az account list --all --only-show-errors -o json 2>/dev/null || echo "[]")"

while IFS= read -r sub; do
  SUB_ID="$(jq -r '.id // empty' <<< "$sub")"
  [[ -z "$SUB_ID" ]] && continue

  # --- ARM GET (read-only) for quotaId & authorizationSource
  ARM_JSON="$(az rest --method get \
              --url "https://management.azure.com/subscriptions/${SUB_ID}?api-version=2020-01-01" \
              -o json 2>/dev/null || echo "{}")"

  HAS_ERROR="$(jq -r 'has("error")' <<< "$ARM_JSON" 2>/dev/null || echo "false")"
  QUOTA_ID=""; AUTH_SRC=""

  if [[ "$HAS_ERROR" != "true" ]]; then
    QUOTA_ID="$(jq -r '.subscriptionPolicies.quotaId // empty' <<< "$ARM_JSON")"
    AUTH_SRC="$(jq -r '.authorizationSource // empty' <<< "$ARM_JSON")"
  fi

  # --- Classify Sub. Type (OFFER)
  OFFER_LABEL=""
  if [[ "$HAS_ERROR" != "true" ]]; then
    OFFER_LABEL="$(offer_from_quota "$QUOTA_ID")"
    [[ -z "$OFFER_LABEL" && "$AUTH_SRC" == "ByPartner" ]] && OFFER_LABEL="CSP"
    [[ -z "$OFFER_LABEL" && "$OVERALL_AGR" =~ MicrosoftCustomerAgreement ]] && OFFER_LABEL="MCA-online"
    [[ -z "$OFFER_LABEL" ]] && OFFER_LABEL="$MISSING"
  else
    # ARM forbidden: avoid guessing; try billing hint; else Not available
    B_SUB="$(az billing subscription show --subscription-id "$SUB_ID" -o json 2>/dev/null || echo "{}")"
    if jq -e 'has("billingAccountId")' <<< "$B_SUB" >/dev/null 2>&1; then
      OFFER_LABEL="MCA-online"
    else
      OFFER_LABEL="$MISSING"
    fi
  fi

  # --- Sub. Owner (ACCOUNT ADMIN / Billing Owner / guidance)
  SUB_OWNER="$MISSING"
  case "$OFFER_LABEL" in
    MSDN|Pay-As-You-Go|EA)
      # Try exact Account Admin via REST
      SUB_OWNER="$(get_classic_account_admin_via_rest "$SUB_ID")"
      if [[ -z "$SUB_OWNER" ]]; then
        # Fallback to guidance when not visible to caller
        if [[ "$OFFER_LABEL" == "EA" ]]; then
          SUB_OWNER="Check in EA portal - Account Owner"
        else
          SUB_OWNER="Check in Portal - classic subscription"
        fi
      fi
      ;;
    MCA-online|MCA-E)
      # Try Billing Owner if permissions allow; otherwise guidance
      BO="$(mca_billing_owner_for_sub "$SUB_ID")"
      if [[ -n "$BO" ]]; then SUB_OWNER="$BO"; else SUB_OWNER="Check in Billing (MCA)"; fi
      ;;
    CSP)
      SUB_OWNER="Managed by partner - CSP"
      ;;
    *)
      SUB_OWNER="$(owner_guidance_for_offer "$OFFER_LABEL")"
      ;;
  esac

  # --- Transferability
  TRANSFER="$(transferable_to_ea "$OFFER_LABEL")"

  printf '"%s","%s","%s","%s"\n' "$SUB_ID" "$OFFER_LABEL" "$SUB_OWNER" "$TRANSFER" >> "$OUT_CSV"
done < <(jq -c '.[]' <<< "$SUBS")

echo
echo "Done."
echo "CSV: $OUT_CSV"
