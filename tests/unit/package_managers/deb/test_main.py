# SPDX-License-Identifier: GPL-3.0-only
from pathlib import Path
from unittest import mock

import pytest
import yaml

from hermeto import APP_NAME
from hermeto.core.errors import (
    ChecksumVerificationFailed,
    InvalidLockfileFormat,
    LockfileNotFound,
)
from hermeto.core.models.input import DebBinaryFilters
from hermeto.core.models.sbom import Annotation, Component, Property
from hermeto.core.package_managers.deb import fetch_deb_source, inject_files_post
from hermeto.core.package_managers.deb.binary_filters import (
    DEBArchitectureFilter,
    UnsatisfiableArchitectureFilter,
)
from hermeto.core.package_managers.deb.debian import DebianDebsLock
from hermeto.core.package_managers.deb.main import (
    Package,
    _download,
    _generate_sbom_components,
    _resolve_deb_project,
    _verify_downloaded,
)
from hermeto.core.rooted_path import RootedPath

DEB_LOCK_FILE_DATA = """
lockfileVersion: 1
lockfileVendor: debian
arches:
  - arch: amd64
    packages:
      - url: https://example.com/pool/main/c/curl/curl_7.88.1-10+deb12u5_amd64.deb
        checksum: sha256:21bb2a09852e75a693d277435c162e1a910835c53c3cee7636dd552d450ed0f1
        size: 311296
        repoid: main
    source:
      - url: https://example.com/pool/main/c/curl/curl_7.88.1-10+deb12u5.dsc
        checksum: sha256:94803b5e1ff601bf4009f223cb53037cdfa2fe559d90251bbe85a3a5bc6d2aab
        size: 2748
        repoid: main-source
"""


@mock.patch("hermeto.core.package_managers.deb.main.create_backend_annotation")
@mock.patch("hermeto.core.package_managers.deb.main.RequestOutput.from_obj_list")
@mock.patch("hermeto.core.package_managers.deb.main._resolve_deb_project")
def test_fetch_deb_source(
    mock_resolve_deb_project: mock.Mock,
    mock_from_obj_list: mock.Mock,
    mock_create_annotation: mock.Mock,
) -> None:
    mock_components = [mock.Mock()]
    mock_resolve_deb_project.return_value = mock_components
    mock_annotation = Annotation(
        subjects=set(),
        annotator={"organization": {"name": "hermeto"}},
        timestamp="2026-01-01T00:00:00Z",
        text="hermeto:backend:x-deb",
    )
    mock_create_annotation.return_value = mock_annotation
    mock_request = mock.Mock()
    mock_request.deb_packages = [mock.Mock(options=None)]
    fetch_deb_source(mock_request)

    mock_resolve_deb_project.assert_called()
    mock_create_annotation.assert_called_with(mock_components, "x-deb")
    mock_from_obj_list.assert_called_with(
        components=mock_components,
        environment_variables=[],
        project_files=[],
        annotations=[mock_annotation],
    )


def test_resolve_deb_project_no_lockfile(rooted_tmp_path: RootedPath) -> None:
    with pytest.raises(LockfileNotFound):
        mock_source_dir = mock.MagicMock()
        mock_source_dir.join_within_root.return_value.path.exists.return_value = False
        _resolve_deb_project(mock_source_dir, mock.Mock())


def test_resolve_deb_project_invalid_yaml_format(rooted_tmp_path: RootedPath) -> None:
    with open(rooted_tmp_path.join_within_root("debs.lock.yaml"), "w") as f:
        # colon is missing at the end
        f.write("lockfileVendor: debian\nlockfileVersion: 1\narches\n")
    with pytest.raises(InvalidLockfileFormat):
        _resolve_deb_project(rooted_tmp_path, rooted_tmp_path)


def test_resolve_deb_project_invalid_lockfile_format(rooted_tmp_path: RootedPath) -> None:
    with open(rooted_tmp_path.join_within_root("debs.lock.yaml"), "w") as f:
        yaml.safe_dump(
            {
                "lockfileVendor": "unknown",
                "lockfileVersion": 1,
                "arches": [],
            },
            f,
        )
    with pytest.raises(InvalidLockfileFormat):
        _resolve_deb_project(rooted_tmp_path, rooted_tmp_path)

    with open(rooted_tmp_path.join_within_root("debs.lock.yaml"), "w") as f:
        yaml.safe_dump(
            {
                "lockfileVendor": "debian",
                "lockfileVersion": 2,
                "arches": [],
            },
            f,
        )
    with pytest.raises(InvalidLockfileFormat):
        _resolve_deb_project(rooted_tmp_path, rooted_tmp_path)

    with open(rooted_tmp_path.join_within_root("debs.lock.yaml"), "w") as f:
        yaml.safe_dump(
            {
                "lockfileVendor": "debian",
                "lockfileVersion": "zz",
                "arches": [],
            },
            f,
        )
    with pytest.raises(InvalidLockfileFormat):
        _resolve_deb_project(rooted_tmp_path, rooted_tmp_path)


def test_resolve_deb_project_arch_empty(rooted_tmp_path: RootedPath) -> None:
    with open(rooted_tmp_path.join_within_root("debs.lock.yaml"), "w") as f:
        yaml.safe_dump(
            {
                "lockfileVendor": "debian",
                "lockfileVersion": 1,
                "arches": [
                    {
                        "arch": "amd64",
                        "packages": [],
                        "source": [],
                    },
                ],
            },
            f,
        )
    with pytest.raises(InvalidLockfileFormat) as exc_info:
        _resolve_deb_project(rooted_tmp_path, rooted_tmp_path)
    assert "At least one field ('packages', 'source') must be set in every arch." in str(
        exc_info.value
    )


@mock.patch("hermeto.core.package_managers.deb.main._download")
def test_resolve_deb_project_correct_format(
    mock_download: mock.Mock, rooted_tmp_path: RootedPath
) -> None:
    with open(rooted_tmp_path.join_within_root("debs.lock.yaml"), "w") as f:
        yaml.safe_dump(
            {
                "lockfileVendor": "debian",
                "lockfileVersion": 1,
                "arches": [
                    {
                        "arch": "amd64",
                        "packages": [
                            {
                                "repoid": "main",
                                "url": "https://example.com/curl_7.88_amd64.deb",
                            },
                        ],
                    },
                ],
            },
            f,
        )
    _resolve_deb_project(rooted_tmp_path, rooted_tmp_path)


@mock.patch(
    "hermeto.core.package_managers.deb.main.open",
    new_callable=mock.mock_open,
)
@mock.patch("hermeto.core.package_managers.deb.main._download")
@mock.patch("hermeto.core.package_managers.deb.main._verify_downloaded")
@mock.patch("hermeto.core.package_managers.deb.main.DebianDebsLock.model_validate")
@mock.patch("hermeto.core.package_managers.deb.main._generate_sbom_components")
def test_resolve_deb_project(
    mock_generate_sbom_components: mock.Mock,
    mock_model_validate: mock.Mock,
    mock_verify_downloaded: mock.Mock,
    mock_download: mock.Mock,
    mock_open: mock.Mock,
) -> None:
    output_dir = mock.Mock()
    mock_package_dir_path = mock.Mock()
    output_dir.join_within_root.return_value.path = mock_package_dir_path
    mock_download.return_value = {}
    mock_model_validate.return_value.lockfileVendor = "debian"

    source_dir = mock.Mock()
    source_dir.subpath_from_root = Path()

    _resolve_deb_project(source_dir, output_dir, None)
    mock_download.assert_called_once()
    call_args = mock_download.call_args
    assert call_args[0][0] == mock_model_validate.return_value
    assert call_args[0][1] == mock_package_dir_path
    assert isinstance(call_args[0][2], DEBArchitectureFilter)
    mock_verify_downloaded.assert_called_once_with({})
    mock_generate_sbom_components.assert_called_once_with({}, Path("debs.lock.yaml"), "debian")


@mock.patch("hermeto.core.package_managers.deb.main.async_download_files")
def test_download(
    mock_async_download_files: mock.Mock,
    rooted_tmp_path: RootedPath,
) -> None:
    lock = DebianDebsLock.model_validate(yaml.safe_load(DEB_LOCK_FILE_DATA))
    _download(lock, rooted_tmp_path.path)
    mock_async_download_files.assert_called_once_with(
        {
            "https://example.com/pool/main/c/curl/curl_7.88.1-10+deb12u5_amd64.deb": str(
                rooted_tmp_path.path.joinpath("amd64/main/curl_7.88.1-10+deb12u5_amd64.deb")
            ),
            "https://example.com/pool/main/c/curl/curl_7.88.1-10+deb12u5.dsc": str(
                rooted_tmp_path.path.joinpath("amd64/main-source/curl_7.88.1-10+deb12u5.dsc")
            ),
        },
        5,
    )


@mock.patch("hermeto.core.package_managers.deb.main.async_download_files")
def test_download_filters_architectures(
    mock_async_download_files: mock.Mock,
    rooted_tmp_path: RootedPath,
) -> None:
    """Test that _download only processes architectures matching the filter."""
    lock = DebianDebsLock.model_validate(
        {
            "lockfileVersion": 1,
            "lockfileVendor": "debian",
            "arches": [
                {"arch": "amd64", "packages": [{"url": "http://amd64.deb"}]},
                {"arch": "arm64", "packages": [{"url": "http://arm64.deb"}]},
            ],
        }
    )

    metadata = _download(
        lock, rooted_tmp_path.path, DEBArchitectureFilter(DebBinaryFilters(arch="amd64"))
    )

    paths = [str(p) for p in metadata.keys()]
    assert all("amd64" in p for p in paths)
    assert not any("arm64" in p for p in paths)


@mock.patch("pathlib.Path.stat")
def test_verify_downloaded_unexpected_size(stat_mock: mock.Mock) -> None:
    stat_mock.return_value = mock.Mock()
    stat_mock.st_size = 0
    metadata = {Path("foo"): {"size": 12345}}

    with pytest.raises(ChecksumVerificationFailed):
        _verify_downloaded(metadata)


def test_verify_downloaded_unsupported_hash_alg() -> None:
    metadata = {Path("foo"): {"checksum": "noalg:unmatchedchecksum", "size": None}}
    with pytest.raises(ChecksumVerificationFailed):
        _verify_downloaded(metadata)


@mock.patch(
    "hermeto.core.package_managers.deb.main.open",
    new_callable=mock.mock_open,
    read_data=b"test",
)
def test_verify_downloaded_unmatched_checksum(mock_open: mock.Mock) -> None:
    metadata = {Path("foo"): {"checksum": "sha256:unmatchedchecksum", "size": None}}
    with pytest.raises(ChecksumVerificationFailed):
        _verify_downloaded(metadata)


class TestDebianDebsLock:
    @pytest.fixture
    def raw_content(self) -> dict:
        return {"lockfileVendor": "debian", "lockfileVersion": 1, "arches": []}

    @mock.patch("hermeto.core.package_managers.deb.debian.uuid")
    def test_internal_repoid(self, mock_uuid: mock.Mock, raw_content: dict) -> None:
        mock_uuid.uuid4.return_value.hex = "abcdefghijklmn"
        lock = DebianDebsLock.model_validate(raw_content)
        assert lock.generated_repoid == f"{APP_NAME}-abcdef"

    @mock.patch("hermeto.core.package_managers.deb.debian.uuid")
    def test_internal_source_repoid(self, mock_uuid: mock.Mock, raw_content: dict) -> None:
        mock_uuid.uuid4.return_value.hex = "abcdefghijklmn"
        lock = DebianDebsLock.model_validate(raw_content)
        assert lock.generated_source_repoid == f"{APP_NAME}-abcdef-source"

    def test_vendor_debian(self, raw_content: dict) -> None:
        raw_content["lockfileVendor"] = "debian"
        lock = DebianDebsLock.model_validate(raw_content)
        assert lock.lockfileVendor == "debian"

    def test_vendor_ubuntu(self, raw_content: dict) -> None:
        raw_content["lockfileVendor"] = "ubuntu"
        lock = DebianDebsLock.model_validate(raw_content)
        assert lock.lockfileVendor == "ubuntu"

    def test_vendor_invalid(self, raw_content: dict) -> None:
        raw_content["lockfileVendor"] = "fedora"
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            DebianDebsLock.model_validate(raw_content)


DEB_FILE = "curl_7.88.1-10+deb12u5_amd64.deb"
DOWNLOAD_URL = f"https://example.com/pool/main/c/curl/{DEB_FILE}"


@pytest.mark.parametrize(
    "metadata,vendor,expected_purl,sbom_properties",
    [
        pytest.param(
            {"repoid": "main", "url": DOWNLOAD_URL, "checksum": "sha256:21bb2a09"},
            "debian",
            None,
            [],
            id="with_repoid_and_checksum",
        ),
        pytest.param(
            {"repoid": "main", "url": DOWNLOAD_URL, "checksum": "sha256:21bb2a09"},
            "ubuntu",
            None,
            [],
            id="with_ubuntu_vendor",
        ),
        pytest.param(
            {"url": DOWNLOAD_URL, "checksum": "sha256:21bb2a09"},
            "debian",
            None,
            [],
            id="no_repoid",
        ),
        pytest.param(
            {"repoid": "main", "url": DOWNLOAD_URL},
            "debian",
            None,
            [Property(name=f"{APP_NAME}:missing_hash:in_file", value="debs.lock.yaml")],
            id="no_checksum",
        ),
    ],
)
@mock.patch("hermeto.core.package_managers.deb.main.subprocess")
def test_generate_sbom_components(
    mock_subprocess: mock.Mock,
    metadata: dict[str, str],
    vendor: str,
    expected_purl: str | None,
    sbom_properties: list[Property],
    tmp_path: Path,
) -> None:
    deb_fields = {
        "name": "curl",
        "version": "7.88.1-10+deb12u5",
        "arch": "amd64",
    }

    deb_file_path = tmp_path / DEB_FILE
    files_metadata = {deb_file_path: metadata}

    mock_result = mock.Mock()
    mock_result.stdout = "\n".join([deb_fields["name"], deb_fields["version"], deb_fields["arch"]])
    mock_subprocess.run.return_value = mock_result

    components = _generate_sbom_components(files_metadata, Path("debs.lock.yaml"), vendor)

    # Build the expected component using the model (which auto-adds found_by property)
    expected_component = Component(
        name=deb_fields["name"],
        version=deb_fields["version"],
        purl=components[0].purl,  # Use actual purl (URL-encoded by packageurl)
        properties=sbom_properties,
    )

    assert len(components) == 1
    assert components == [expected_component]

    # Verify PURL contains expected components
    component = components[0]
    assert f"pkg:deb/{vendor}/" in component.purl
    assert deb_fields["name"] in component.purl
    if metadata.get("repoid"):
        assert f"repository_id={metadata['repoid']}" in component.purl
    if metadata.get("checksum"):
        assert "checksum=" in component.purl
    if not metadata.get("repoid") and metadata.get("url"):
        assert "download_url=" in component.purl


def test_filter_arches_all() -> None:
    """Test that None filter returns all arches."""
    arches = [mock.Mock(arch="amd64"), mock.Mock(arch="arm64")]
    arch_filter = DEBArchitectureFilter(None)
    result = arch_filter.validate_and_filter(arches)
    assert len(result) == 2


def test_filter_arches_specific() -> None:
    """Test that specific filter returns only matching arches."""
    arches = [mock.Mock(arch="amd64"), mock.Mock(arch="arm64")]
    arch_filter = DEBArchitectureFilter(DebBinaryFilters(arch="amd64"))
    result = arch_filter.validate_and_filter(arches)
    assert len(result) == 1
    assert result[0].arch == "amd64"


def test_filter_arches_unsatisfiable() -> None:
    """Test that unsatisfiable filter raises UnsatisfiableArchitectureFilter."""
    arches = [mock.Mock(arch="amd64"), mock.Mock(arch="arm64")]
    arch_filter = DEBArchitectureFilter(DebBinaryFilters(arch="s390x"))
    with pytest.raises(UnsatisfiableArchitectureFilter, match="s390x"):
        arch_filter.validate_and_filter(arches)


@mock.patch("hermeto.core.package_managers.deb.main.Path")
@mock.patch("hermeto.core.package_managers.deb.main._generate_sources_list")
@mock.patch("hermeto.core.package_managers.deb.main._generate_packages_index")
def test_inject_files_post(
    mock_gen_packages: mock.Mock,
    mock_gen_sources: mock.Mock,
    mock_path: mock.Mock,
    rooted_tmp_path: RootedPath,
) -> None:
    inject_files_post(from_output_dir=rooted_tmp_path.path, for_output_dir=rooted_tmp_path.path)


def test_package_parse_deb_filename() -> None:
    """Test the filename parsing fallback."""
    result = Package._parse_deb_filename(Path("curl_7.88.1-10_amd64.deb"))
    assert result == {"name": "curl", "version": "7.88.1-10", "arch": "amd64"}

    result = Package._parse_deb_filename(Path("curl_7.88.deb"))
    assert result == {"name": "curl", "version": "7.88", "arch": "all"}

    result = Package._parse_deb_filename(Path("curl.deb"))
    assert result == {"name": "curl", "version": "unknown", "arch": "all"}
