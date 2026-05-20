from __future__ import annotations

import json

import pytest

from lemonade_security.aibom import AibomComponent, local_manifest, to_cyclonedx_json

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _manifest_with(**kwargs: object) -> dict:  # type: ignore[type-arg]
    defaults: dict = {
        "store_id": "tie-dye-farms",
        "components": (),
    }
    defaults.update(kwargs)
    return local_manifest(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Backward-compatibility: original test still passes
# ---------------------------------------------------------------------------

def test_local_manifest_records_components() -> None:
    manifest = local_manifest(
        store_id="tie-dye-farms",
        components=(
            AibomComponent(
                kind="plugin",
                name="lemonade-sdk-security",
                location="plugins/lemonade-sdk-security",
            ),
        ),
    )

    assert manifest["schema"] == "lemonade.security.aibom.v0"
    assert manifest["store_id"] == "tie-dye-farms"
    assert manifest["components"][0]["name"] == "lemonade-sdk-security"


# ---------------------------------------------------------------------------
# CycloneDX 1.6 top-level shape
# ---------------------------------------------------------------------------

def test_bom_format() -> None:
    assert _manifest_with()["bomFormat"] == "CycloneDX"


def test_spec_version() -> None:
    assert _manifest_with()["specVersion"] == "1.6"


def test_serial_number_format() -> None:
    sn = _manifest_with()["serialNumber"]
    assert sn.startswith("urn:uuid:")
    # UUID v5 is deterministic for the same store_id
    assert sn == _manifest_with()["serialNumber"]


def test_serial_number_differs_by_store_id() -> None:
    sn_a = _manifest_with(store_id="store-alpha")["serialNumber"]
    sn_b = _manifest_with(store_id="store-beta")["serialNumber"]
    assert sn_a != sn_b


def test_bom_version_is_one() -> None:
    assert _manifest_with()["version"] == 1


def test_metadata_component_present() -> None:
    meta = _manifest_with()["metadata"]
    assert meta["component"]["name"] == "lemonade-security"


def test_metadata_timestamp_present() -> None:
    ts = _manifest_with()["metadata"]["timestamp"]
    # ISO-8601 UTC — must contain date separator and time separator
    assert "T" in ts
    assert ts.endswith("Z")


# ---------------------------------------------------------------------------
# kind → CycloneDX type mapping
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("kind", "expected_type"),
    [
        ("model", "machine-learning-model"),
        ("data", "data"),
        ("plugin", "library"),
        ("tool", "library"),
        ("department", "library"),
        ("unknown-thing", "library"),
    ],
)
def test_kind_maps_to_cdx_type(kind: str, expected_type: str) -> None:
    manifest = local_manifest(
        store_id="test-store",
        components=(AibomComponent(kind=kind, name="some-component"),),
    )
    assert manifest["components"][0]["type"] == expected_type


# ---------------------------------------------------------------------------
# Component field mapping
# ---------------------------------------------------------------------------

def test_component_bom_ref_is_slugified() -> None:
    manifest = local_manifest(
        store_id="My Store",
        components=(AibomComponent(kind="plugin", name="Fancy Plugin"),),
    )
    assert manifest["components"][0]["bom-ref"] == "my-store/fancy-plugin"


def test_component_version_included_when_present() -> None:
    manifest = local_manifest(
        store_id="s",
        components=(AibomComponent(kind="model", name="llama", version="3.1"),),
    )
    assert manifest["components"][0]["version"] == "3.1"


def test_component_version_absent_when_none() -> None:
    manifest = local_manifest(
        store_id="s",
        components=(AibomComponent(kind="model", name="llama"),),
    )
    assert "version" not in manifest["components"][0]


def test_component_supplier_name_when_present() -> None:
    manifest = local_manifest(
        store_id="s",
        components=(AibomComponent(kind="plugin", name="p", supplier="Acme"),),
    )
    assert manifest["components"][0]["supplier"]["name"] == "Acme"


def test_component_supplier_absent_when_none() -> None:
    manifest = local_manifest(
        store_id="s",
        components=(AibomComponent(kind="plugin", name="p"),),
    )
    assert "supplier" not in manifest["components"][0]


def test_component_description_from_notes() -> None:
    manifest = local_manifest(
        store_id="s",
        components=(AibomComponent(kind="tool", name="scanner", notes="detects CVEs"),),
    )
    assert manifest["components"][0]["description"] == "detects CVEs"


def test_component_description_absent_when_no_notes() -> None:
    manifest = local_manifest(
        store_id="s",
        components=(AibomComponent(kind="tool", name="scanner"),),
    )
    assert "description" not in manifest["components"][0]


# ---------------------------------------------------------------------------
# to_cyclonedx_json
# ---------------------------------------------------------------------------

def test_to_cyclonedx_json_is_valid_json() -> None:
    manifest = _manifest_with(
        components=(AibomComponent(kind="model", name="qwen", version="3.5"),)
    )
    raw = to_cyclonedx_json(manifest)
    parsed = json.loads(raw)  # must not raise
    assert parsed["bomFormat"] == "CycloneDX"


def test_to_cyclonedx_json_is_indented() -> None:
    raw = to_cyclonedx_json(_manifest_with())
    assert "\n" in raw
