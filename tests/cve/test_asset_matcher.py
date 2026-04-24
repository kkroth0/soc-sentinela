import pytest
from cve.asset_matcher import match_cve_to_clients

# --- HAPPY PATH ---
def test_should_match_cve_when_vendor_and_product_exist_in_asset_map():
    asset_map = {"microsoft": ["Global SOC"], "windows": ["Global SOC"]}
    cve = {"vendor": "Microsoft", "product": "Windows", "affected_products": [("microsoft", "windows")]}
    
    matches = match_cve_to_clients(cve, asset_map)
    assert "Global SOC" in matches

def test_should_match_via_affected_products_when_primary_vendor_fails():
    asset_map = {"linux": ["Client A"]}
    cve = {
        "vendor": "Unknown", 
        "product": "Unknown", 
        "affected_products": [("linux", "kernel"), ("apache", "httpd")]
    }
    matches = match_cve_to_clients(cve, asset_map)
    assert "Client A" in matches

# --- EDGE CASES ---
def test_should_return_empty_list_when_no_matches_found():
    asset_map = {"apple": ["Client B"]}
    cve = {"vendor": "Microsoft", "product": "Office", "affected_products": []}
    matches = match_cve_to_clients(cve, asset_map)
    assert matches == []

def test_should_return_empty_list_when_asset_map_is_empty():
    cve = {"vendor": "Microsoft", "product": "Office", "affected_products": [("microsoft", "office")]}
    matches = match_cve_to_clients(cve, {})
    assert matches == []

# --- MALFORMED DATA ---
def test_should_handle_missing_keys_gracefully():
    asset_map = {"microsoft": ["Global SOC"]}
    # CVE incompleta sem 'affected_products'
    cve = {"vendor": "Microsoft", "product": "Office"}
    
    # A função deve lidar com a ausência de chaves sem explodir
    matches = match_cve_to_clients(cve, asset_map)
    assert "Global SOC" in matches
