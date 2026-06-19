package fed.inventory_test

import rego.v1

import data.fed.inventory

# --- FIXTURE A: withheld+Retired (expect: 0 errors — suppression works, all 9 always-required present) ---
_fixture_a := {
	"agency": "DOL",
	"agency_name": "Department of Labor",
	"id": "DOL-26",
	"use_case_name": "Web Scraping to Identify Potentially Fraudulent MEWAs",
	"agency_bureau": "EBSA",
	"contact_email": "zzOCIO-AI@dol.gov",
	"is_withheld": "Yes - Prohibited by Law",
	"development_stage": "Retired",
	"is_high_impact": "Not High-impact",
	"HI_justification": "Discontinued pre-deployment",
	"topic_area": "",
	"classification": "",
	"problem_solved": "",
	"benefits": "",
	"system_outputs": "",
	"operational_date": "",
	"contracting_usage": "",
	"vendor_name": "",
	"have_ato": "",
	"system_name_ato": "",
	"data_description": "",
	"link_to_data": "",
	"has_pii": "",
	"pia_url": "",
	"demographic_features": "[]",
	"has_custom_code": "",
	"code_url": "",
	"hi_testing_conducted": "",
	"hi_assessment_completed": "",
	"hi_potential_impacts": "",
	"hi_independent_review": "",
	"hi_ongoing_monitoring": "",
	"hi_training_established": "",
	"hi_failsafe_presence": "",
	"hi_appeal_process": "",
	"hi_public_consultation": "[]",
}

# --- FIXTURE B: CFTC Pre-deployment with blank is_withheld/is_high_impact/contact_email (expect: 7 errors) ---
_fixture_b := {
	"agency": "CFTC",
	"agency_name": "Commodity Futures Trading Commission",
	"id": "CFTC-003",
	"use_case_name": "Stress Testing Scenarios with Deep Learning",
	"agency_bureau": "DCR",
	"contact_email": "",
	"is_withheld": "",
	"development_stage": "Pre-deployment",
	"is_high_impact": "",
	"HI_justification": "",
	"topic_area": "",
	"classification": "",
	"problem_solved": "Pilot project to explore neural-network ML methods for stress testing scenarios.",
	"benefits": "",
	"system_outputs": "",
	"operational_date": "",
	"contracting_usage": "",
	"vendor_name": "",
	"have_ato": "",
	"system_name_ato": "",
	"data_description": "",
	"link_to_data": "",
	"has_pii": "",
	"pia_url": "",
	"demographic_features": "[]",
	"has_custom_code": "",
	"code_url": "",
	"hi_testing_conducted": "",
	"hi_assessment_completed": "",
	"hi_potential_impacts": "",
	"hi_independent_review": "",
	"hi_ongoing_monitoring": "",
	"hi_training_established": "",
	"hi_failsafe_presence": "",
	"hi_appeal_process": "",
	"hi_public_consultation": "[]",
}

# --- FIXTURE C: CFTC Pilot, blanks (expect: 13 errors — required + tier-A + tier-B) ---
_fixture_c := {
	"agency": "CFTC",
	"agency_name": "Commodity Futures Trading Commission",
	"id": "CFTC-004",
	"use_case_name": "MPD Entity Risk Modeling",
	"agency_bureau": "MPD",
	"contact_email": "",
	"is_withheld": "",
	"development_stage": "Pilot",
	"is_high_impact": "",
	"HI_justification": "",
	"topic_area": "",
	"classification": "",
	"problem_solved": "Entity-level risk modeling; early R&D.",
	"benefits": "",
	"system_outputs": "",
	"operational_date": "",
	"contracting_usage": "",
	"vendor_name": "",
	"have_ato": "",
	"system_name_ato": "",
	"data_description": "",
	"link_to_data": "",
	"has_pii": "",
	"pia_url": "",
	"demographic_features": "[]",
	"has_custom_code": "",
	"code_url": "",
	"hi_testing_conducted": "",
	"hi_assessment_completed": "",
	"hi_potential_impacts": "",
	"hi_independent_review": "",
	"hi_ongoing_monitoring": "",
	"hi_training_established": "",
	"hi_failsafe_presence": "",
	"hi_appeal_process": "",
	"hi_public_consultation": "[]",
}

# --- FIXTURE D: CFTC Deployed, blanks (expect: 13 errors — required + tier-A + tier-B) ---
_fixture_d := {
	"agency": "CFTC",
	"agency_name": "Commodity Futures Trading Commission",
	"id": "CFTC-001",
	"use_case_name": "Anomaly Detection for Data Quality",
	"agency_bureau": "DOD",
	"contact_email": "",
	"is_withheld": "",
	"development_stage": "Deployed",
	"is_high_impact": "",
	"HI_justification": "",
	"topic_area": "",
	"classification": "",
	"problem_solved": "Isolation-forest anomaly detection on TCR data, runs daily.",
	"benefits": "",
	"system_outputs": "",
	"operational_date": "",
	"contracting_usage": "",
	"vendor_name": "",
	"have_ato": "",
	"system_name_ato": "",
	"data_description": "",
	"link_to_data": "",
	"has_pii": "",
	"pia_url": "",
	"demographic_features": "[]",
	"has_custom_code": "",
	"code_url": "",
	"hi_testing_conducted": "",
	"hi_assessment_completed": "",
	"hi_potential_impacts": "",
	"hi_independent_review": "",
	"hi_ongoing_monitoring": "",
	"hi_training_established": "",
	"hi_failsafe_presence": "",
	"hi_appeal_process": "",
	"hi_public_consultation": "[]",
}

# --- FIXTURE E: DHS High-impact Deployed, fully populated (expect: 0 errors) ---
_fixture_e := {
	"agency": "DHS",
	"agency_name": "Department of Homeland Security",
	"id": "DHS-185",
	"use_case_name": "Babel",
	"agency_bureau": "CBP",
	"contact_email": "ai@hq.dhs.gov",
	"is_withheld": "No",
	"development_stage": "Deployed",
	"is_high_impact": "High-impact",
	"HI_justification": "",
	"topic_area": "Law Enforcement",
	"classification": "NLP",
	"problem_solved": "AI text detection/translation and image recognition surfacing analyst review candidates.",
	"benefits": "Targeted open-source research to identify potential threats.",
	"system_outputs": "Possible matches for manual analyst review; not solely used for action.",
	"operational_date": "2023-08-29 00:00:00",
	"contracting_usage": "Contracting and In House",
	"vendor_name": "Babel Street",
	"have_ato": "Yes",
	"system_name_ato": "Babel Street",
	"data_description": "Proprietary, public, and machine-labeled datasets; human-annotated evaluation.",
	"link_to_data": "",
	"has_pii": "Yes",
	"pia_url": "https://www.dhs.gov/publication/dhscbppia-058",
	"demographic_features": "[]",
	"has_custom_code": "No",
	"code_url": "",
	"hi_testing_conducted": "Yes",
	"hi_assessment_completed": "In-progress",
	"hi_potential_impacts": "Inaccurate translation risk mitigated by certified linguists.",
	"hi_independent_review": "In-progress",
	"hi_ongoing_monitoring": "In-progress",
	"hi_training_established": "Training In-progress",
	"hi_failsafe_presence": "In-progress",
	"hi_appeal_process": "Appeal Process Established",
	"hi_public_consultation": "['Other']",
}

# --- FIXTURE F: DHS vendor Pilot, "Presumed High-Impact, but Not High-impact" with HI_justification (expect: 0 errors) ---
_fixture_f := {
	"agency": "DHS",
	"agency_name": "Department of Homeland Security",
	"id": "DHS-2572",
	"use_case_name": "Acoustic Signature AI for Gunshot Detection",
	"agency_bureau": "CBP",
	"contact_email": "ai@hq.dhs.gov",
	"is_withheld": "No",
	"development_stage": "Pilot",
	"is_high_impact": "Presumed High-Impact, but Not High-impact",
	"HI_justification": "High-confidence gunshot events are reviewed by users; AI is not the principal basis for action.",
	"topic_area": "Law Enforcement",
	"classification": "Classical ML",
	"problem_solved": "Distinguish gunshot vs non-gunshot acoustic activity to reduce false alerts.",
	"benefits": "Enhanced situational awareness with GPS-located alerts.",
	"system_outputs": "Real-time text notifications with location and audio link.",
	"operational_date": "2025-09-08 00:00:00",
	"contracting_usage": "Vendor Purchased",
	"vendor_name": "Invariant Corporation",
	"have_ato": "No",
	"system_name_ato": "",
	"data_description": "Vendor-trained on vendor audio; refined during deployments.",
	"link_to_data": "",
	"has_pii": "No",
	"pia_url": "",
	"demographic_features": "[]",
	"has_custom_code": "No",
	"code_url": "",
	"hi_testing_conducted": "",
	"hi_assessment_completed": "",
	"hi_potential_impacts": "",
	"hi_independent_review": "",
	"hi_ongoing_monitoring": "",
	"hi_training_established": "",
	"hi_failsafe_presence": "",
	"hi_appeal_process": "",
	"hi_public_consultation": "[]",
}

# --- FIXTURE G1: FRB Deployed with topic_area "Other – Economic & Financial" (KEY test for FIX 1) ---
_fixture_g1 := {
	"agency": "FRB",
	"agency_name": "Federal Reserve Board",
	"id": "FRB-0026",
	"use_case_name": "Consumer Complaints Explorer",
	"agency_bureau": "Division of Consumer and Community Affairs",
	"contact_email": "complaints@frb.gov",
	"is_withheld": "No",
	"development_stage": "Deployed",
	"is_high_impact": "Not High-impact",
	"HI_justification": "",
	"topic_area": "Other – Economic & Financial",
	"classification": "NLP",
	"problem_solved": "Categorize consumer complaints into topics.",
	"benefits": "Improve complaint classification via topic modeling.",
	"system_outputs": "Gamma value, topic number, and top five terms per narrative.",
	"operational_date": "2019-01-01 00:00:00",
	"contracting_usage": "In-house Development",
	"vendor_name": "",
	"have_ato": "Yes",
	"system_name_ato": "General Support System",
	"data_description": "External – CFPB Consumer Complaints",
	"link_to_data": "",
	"has_pii": "No",
	"pia_url": "",
	"demographic_features": "['k) None of the above']",
	"has_custom_code": "Yes",
	"code_url": "",
	"hi_testing_conducted": "",
	"hi_assessment_completed": "",
	"hi_potential_impacts": "",
	"hi_independent_review": "",
	"hi_ongoing_monitoring": "",
	"hi_training_established": "",
	"hi_failsafe_presence": "",
	"hi_appeal_process": "",
	"hi_public_consultation": "[]",
}

# --- FIXTURE G2: FRB Pre-deployment with "Other – …" topic_area (expect: 0 errors) ---
_fixture_g2 := {
	"agency": "FRB",
	"agency_name": "Federal Reserve Board",
	"id": "FRB-0051",
	"use_case_name": "Financial System Data Analysis",
	"agency_bureau": "Division of Financial Stability",
	"contact_email": "fsda@frb.gov",
	"is_withheld": "No",
	"development_stage": "Pre-deployment",
	"is_high_impact": "Not High-impact",
	"HI_justification": "",
	"topic_area": "Other – Economic & Financial",
	"classification": "Classical ML",
	"problem_solved": "Model counterparty exposures across institutions.",
	"benefits": "Enhance monitoring of financial-system trends.",
	"system_outputs": "Calculated risk score.",
	"operational_date": "",
	"contracting_usage": "",
	"vendor_name": "",
	"have_ato": "",
	"system_name_ato": "",
	"data_description": "",
	"link_to_data": "",
	"has_pii": "",
	"pia_url": "",
	"demographic_features": "[]",
	"has_custom_code": "",
	"code_url": "",
	"hi_testing_conducted": "",
	"hi_assessment_completed": "",
	"hi_potential_impacts": "",
	"hi_independent_review": "",
	"hi_ongoing_monitoring": "",
	"hi_training_established": "",
	"hi_failsafe_presence": "",
	"hi_appeal_process": "",
	"hi_public_consultation": "[]",
}

# === TESTS ===

# Test 1: Fixture A — withheld case suppresses detail requirements (0 errors)
test_fixture_a_withheld_suppression if {
	results := inventory.deny with input as _fixture_a
	count(results) == 0
	inventory.valid with input as _fixture_a
}

# Test 2: Fixture B — Pre-deployment with missing required + tier A (7 errors)
test_fixture_b_missing_required_and_tier_a if {
	results := inventory.deny with input as _fixture_b
	count(results) == 7
	errors := {d | some d in results; d.severity == "error"}
	count(errors) == 7
	required_errors := {d | some d in results; d.rule == "required"}
	count(required_errors) == 3 # contact_email, is_withheld, is_high_impact
	tier_a_errors := {d | some d in results; d.rule == "tier_a"}
	count(tier_a_errors) == 4 # topic_area, classification, benefits, system_outputs (problem_solved present)
}

# Test 3: Fixture C — Pilot with missing required + tier A + tier B (13 errors)
test_fixture_c_pilot_missing_all_tiers if {
	results := inventory.deny with input as _fixture_c
	count(results) == 13
	errors := {d | some d in results; d.severity == "error"}
	count(errors) == 13
	tier_b_errors := {d | some d in results; d.rule == "tier_b"}
	count(tier_b_errors) > 0
}

# Test 4: Fixture D — Deployed with missing required + tier A + tier B (13 errors)
test_fixture_d_deployed_missing_all_tiers if {
	results := inventory.deny with input as _fixture_d
	count(results) == 13
	errors := {d | some d in results; d.severity == "error"}
	count(errors) == 13
}

# Test 5: Fixture E — High-impact Deployed fully populated (0 errors)
test_fixture_e_high_impact_complete if {
	results := inventory.deny with input as _fixture_e
	count(results) == 0
	inventory.valid with input as _fixture_e
}

# Test 6: Fixture F — Presumed High-Impact with HI_justification (0 errors)
test_fixture_f_presumed_high_impact_with_justification if {
	results := inventory.deny with input as _fixture_f
	count(results) == 0
	inventory.valid with input as _fixture_f
}

# Test 7: Fixture G1 — "Other – …" topic_area accepted (NO topic_area enum warning)
test_fixture_g1_other_topic_area_accepted if {
	results := inventory.deny with input as _fixture_g1
	count(results) == 0
	inventory.valid with input as _fixture_g1

	# Ensure NO topic_area enum violation
	topic_errors := {d | some d in results; d.field == "topic_area"; d.rule == "enum"}
	count(topic_errors) == 0
}

# Test 8: Fixture G2 — Pre-deployment with "Other – …" topic_area (0 errors)
test_fixture_g2_pre_deployment_other_topic if {
	results := inventory.deny with input as _fixture_g2
	count(results) == 0
	inventory.valid with input as _fixture_g2
}

# Test 9: Withholding logic works with BOTH dash variants (en-dash and hyphen)
test_withholding_dash_variants if {
	# Test en-dash variant
	input_en_dash := object.union(_fixture_a, {"is_withheld": "Yes – Disclosure Risk"})
	results_en := inventory.deny with input as input_en_dash
	count(results_en) == 0

	# Test hyphen variant
	input_hyphen := object.union(_fixture_a, {"is_withheld": "Yes - Disclosure Risk"})
	results_hy := inventory.deny with input as input_hyphen
	count(results_hy) == 0
}

# Test 10: Missing tier C fields for High-impact Deployed
test_missing_tier_c_high_impact if {
	# High-impact Deployed with all tier C fields absent
	incomplete_hi := object.union(_fixture_e, {
		"hi_testing_conducted": "",
		"hi_assessment_completed": "",
		"hi_potential_impacts": "",
		"hi_independent_review": "",
		"hi_ongoing_monitoring": "",
		"hi_training_established": "",
		"hi_failsafe_presence": "",
		"hi_appeal_process": "",
		"hi_public_consultation": "",
	})
	results := inventory.deny with input as incomplete_hi
	tier_c_errors := {d | some d in results; d.rule == "tier_c"}
	count(tier_c_errors) == 9
}

# Test 11: Vendor name required when contracting_usage demands it
test_vendor_name_required if {
	# Pilot with Vendor Purchased but no vendor_name
	no_vendor := object.union(_fixture_f, {"vendor_name": ""})
	results := inventory.deny with input as no_vendor
	vendor_errors := {d | some d in results; d.rule == "vendor_name"}
	count(vendor_errors) == 1
}

# Test 12: System name ATO required when have_ato=Yes
test_system_name_ato_required if {
	# Deployed with have_ato=Yes but no system_name_ato
	no_ato_name := object.union(_fixture_g1, {"system_name_ato": ""})
	results := inventory.deny with input as no_ato_name
	ato_errors := {d | some d in results; d.rule == "system_name_ato"}
	count(ato_errors) == 1
}

# Test 13: HI_justification required for "Presumed High-Impact, but Not High-impact"
test_hi_justification_required if {
	# Presumed High-Impact without justification
	no_justification := object.union(_fixture_f, {"HI_justification": ""})
	results := inventory.deny with input as no_justification
	hi_just_errors := {d | some d in results; d.rule == "hi_justification"}
	count(hi_just_errors) == 1
}

# Test 14: Invalid enum values produce warnings
test_invalid_enum_warnings if {
	bad_enums := {
		"agency": "TEST",
		"agency_name": "Test",
		"id": "T-1",
		"use_case_name": "Test",
		"agency_bureau": "Test",
		"contact_email": "invalid-email",
		"is_withheld": "Maybe",
		"development_stage": "In Progress",
		"is_high_impact": "Unknown",
		"HI_justification": "",
		"topic_area": "Space Exploration",
		"classification": "Quantum AI",
		"problem_solved": "Test",
		"benefits": "Test",
		"system_outputs": "Test",
		"operational_date": "",
		"contracting_usage": "DIY",
		"vendor_name": "",
		"have_ato": "Maybe",
		"system_name_ato": "",
		"data_description": "",
		"link_to_data": "",
		"has_pii": "Unknown",
		"pia_url": "",
		"demographic_features": "[]",
		"has_custom_code": "Unknown",
		"code_url": "",
		"hi_testing_conducted": "",
		"hi_assessment_completed": "",
		"hi_potential_impacts": "",
		"hi_independent_review": "",
		"hi_ongoing_monitoring": "",
		"hi_training_established": "",
		"hi_failsafe_presence": "",
		"hi_appeal_process": "",
		"hi_public_consultation": "[]",
	}
	results := inventory.deny with input as bad_enums
	warnings := {d | some d in results; d.severity == "warning"}
	count(warnings) >= 7 # Multiple enum and format violations
	enum_warnings := {d | some d in results; d.rule == "enum"}
	count(enum_warnings) >= 6
}

# Test 15: Format validation catches bad email and empty id
test_format_validation if {
	bad_format := object.union(_fixture_g2, {
		"contact_email": "invalid-email-no-at",
		"id": "   ",
	})
	results := inventory.deny with input as bad_format
	format_errors := {d | some d in results; d.rule == "format"}
	count(format_errors) == 2
}

# --- COTS VARIANT TESTS (fixtures from real 2025_consolidated_COTS_AI_use_cases.csv) ---

# COTS Fixture 1: fully conformant COTS record with product usage
_cots_fixture_1 := {
	"Agency": "Committee for Purchase From People Who Are Blind or Significantly Disabled",
	"AI Use Case": "Transcribing, summarizing, or other efforts that improve the accessibility of a virtual meeting or interview using AI.",
	"Agency Use (Y/N)?": "Y",
	"Name of Commercial Product or Service Used": "Microsoft 365 Copilot GCC",
	"Estimated # of Licenses/Users": "1-100",
}

# COTS Fixture 2: COTS record with Agency Use = N (product fields should be empty/optional)
_cots_fixture_2 := {
	"Agency": "Committee for Purchase From People Who Are Blind or Significantly Disabled",
	"AI Use Case": "Scheduling internal-to-government meetings or appointments or set reminders using AI.",
	"Agency Use (Y/N)?": "N",
	"Name of Commercial Product or Service Used": "",
	"Estimated # of Licenses/Users": "",
}

# COTS Fixture 3: incomplete COTS record (missing required fields)
_cots_fixture_3 := {
	"Agency": "",
	"AI Use Case": "Prioritizing and categorizing incoming emails using AI.",
	"Agency Use (Y/N)?": "",
	"Name of Commercial Product or Service Used": "",
	"Estimated # of Licenses/Users": "",
}

# COTS Fixture 4: COTS record with Agency Use = Y but missing product fields
_cots_fixture_4 := {
	"Agency": "Department of Defense",
	"AI Use Case": "AI-powered threat detection",
	"Agency Use (Y/N)?": "Y",
	"Name of Commercial Product or Service Used": "",
	"Estimated # of Licenses/Users": "",
}

# Test 16: COTS conformant record with Agency Use = Y (0 warnings)
test_cots_conformant_with_usage if {
	results := inventory.cots_deny with input as _cots_fixture_1
	count(results) == 0
	summary := inventory.cots_summary with input as _cots_fixture_1
	summary.valid
}

# Test 17: COTS conformant record with Agency Use = N (0 warnings)
test_cots_conformant_without_usage if {
	results := inventory.cots_deny with input as _cots_fixture_2
	count(results) == 0
	summary := inventory.cots_summary with input as _cots_fixture_2
	summary.valid
}

# Test 18: COTS incomplete record missing required fields (2 warnings)
test_cots_missing_required if {
	results := inventory.cots_deny with input as _cots_fixture_3
	count(results) == 2 # Agency (empty), Agency Use (Y/N)? (empty); AI Use Case has value
	required_errors := {d | some d in results; d.rule == "cots_required"}
	count(required_errors) == 2
}

# Test 19: COTS record with Agency Use = Y but missing product fields (2 warnings)
test_cots_missing_product_fields if {
	results := inventory.cots_deny with input as _cots_fixture_4
	count(results) == 2
	product_errors := {d | some d in results; d.rule == "cots_required_if_used"}
	count(product_errors) == 2
}

# Test 20: COTS record with invalid Agency Use enum value (1 warning)
test_cots_invalid_enum if {
	bad_cots := object.union(_cots_fixture_1, {"Agency Use (Y/N)?": "Maybe"})
	results := inventory.cots_deny with input as bad_cots
	enum_errors := {d | some d in results; d.rule == "cots_enum"}
	count(enum_errors) == 1
}
