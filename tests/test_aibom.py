from __future__ import annotations

from lemonade_security.aibom import AibomComponent, local_manifest


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
