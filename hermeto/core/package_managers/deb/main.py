# SPDX-License-Identifier: GPL-3.0-only
"""Debian/Ubuntu .deb package manager backend for hermeto."""

import asyncio
import hashlib
import itertools
import logging
import subprocess
from dataclasses import dataclass
from os import PathLike
from pathlib import Path
from typing import Any

import yaml
from packageurl import PackageURL
from pydantic import ValidationError

from hermeto import APP_NAME
from hermeto.core.config import get_config
from hermeto.core.errors import (
    ChecksumVerificationFailed,
    InvalidLockfileFormat,
    LockfileNotFound,
)
from hermeto.core.models.input import DebBinaryFilters, Request
from hermeto.core.package_managers.deb.binary_filters import DEBArchitectureFilter
from hermeto.core.models.output import RequestOutput
from hermeto.core.models.sbom import Component, Property, create_backend_annotation
from hermeto.core.package_managers.deb.debian import DebianDebsLock
from hermeto.core.package_managers.general import async_download_files
from hermeto.core.rooted_path import RootedPath

log = logging.getLogger(__name__)


DEFAULT_LOCKFILE_NAME = "debs.lock.yaml"
DEFAULT_PACKAGE_DIR = "deps/deb"

# during the computing of file checksum read chunk of size 1 MB
READ_CHUNK = 1048576


@dataclass
class Package:
    """A .deb package with relevant data for the SBOM generation."""

    name: str
    version: str
    arch: str
    download_url: str
    vendor: str | None = None
    checksum: str | None = None
    repository_id: str | None = None

    @classmethod
    def from_filepath(
        cls, deb_filepath: Path, deb_download_metadata: dict[str, Any], lockfile_vendor: str
    ) -> "Package":
        """Instantiate a package dataclass instance from a downloaded .deb file path."""
        kwargs: dict[str, str | None] = {}
        kwargs.update(cls._query_deb_fields(deb_filepath))

        repoid = deb_download_metadata.get("repoid")

        kwargs["repository_id"] = (
            repoid if repoid and not repoid.startswith(f"{APP_NAME}") else None
        )
        kwargs["download_url"] = deb_download_metadata["url"]
        kwargs["checksum"] = deb_download_metadata.get("checksum")
        kwargs["vendor"] = lockfile_vendor

        package = cls(**kwargs)  # type: ignore
        log.debug("DEB package attributes for '%s': %s", deb_filepath, package)
        return package

    @staticmethod
    def _query_deb_fields(file_path: Path) -> dict[str, str]:
        """Query a set of .deb package fields using dpkg-deb.

        Returns name, version, and architecture from the .deb control metadata.
        """
        ret = {}
        try:
            output = subprocess.run(
                [  # noqa: S607
                    "dpkg-deb",
                    "--showformat",
                    "${Package}\n${Version}\n${Architecture}\n",
                    "-W",
                    str(file_path),
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            lines = output.stdout.strip().split("\n")
            if len(lines) >= 3:
                ret["name"] = lines[0]
                ret["version"] = lines[1]
                ret["arch"] = lines[2]
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            log.warning(
                "Could not query .deb metadata for '%s': %s. Falling back to filename parsing.",
                file_path,
                e,
            )
            ret.update(Package._parse_deb_filename(file_path))

        return ret

    @staticmethod
    def _parse_deb_filename(file_path: Path) -> dict[str, str]:
        """Parse package metadata from the .deb filename as a fallback.

        Expected format: <name>_<version>_<arch>.deb
        """
        stem = file_path.stem
        parts = stem.split("_")
        ret: dict[str, str] = {}
        if len(parts) >= 3:
            ret["name"] = parts[0]
            ret["version"] = parts[1]
            ret["arch"] = parts[2]
        elif len(parts) == 2:
            ret["name"] = parts[0]
            ret["version"] = parts[1]
            ret["arch"] = "all"
        else:
            ret["name"] = stem
            ret["version"] = "unknown"
            ret["arch"] = "all"
        return ret

    @property
    def purl(self) -> str:
        """Get the purl for this package."""
        qualifier_fields = [
            ("arch", self.arch),
            ("repository_id", self.repository_id),
            ("checksum", self.checksum),
            ("download_url", None if self.repository_id else self.download_url),
        ]
        qualifiers: dict[str, str] = {k: v for k, v in qualifier_fields if v is not None}

        # The PURL spec treats debian and ubuntu as distinct namespaces
        namespace = self.vendor if self.vendor else ""

        return PackageURL(
            type="deb",
            name=self.name,
            namespace=namespace,
            version=self.version,
            qualifiers=qualifiers,
        ).to_string()

    def to_component(self, lockfile_path: Path) -> Component:
        """Create an SBOM component for this package."""
        properties = []
        if not self.checksum:
            properties = [
                Property(name=f"{APP_NAME}:missing_hash:in_file", value=str(lockfile_path))
            ]

        return Component(
            name=self.name, version=self.version, purl=self.purl, properties=properties
        )


def fetch_deb_source(request: Request) -> RequestOutput:
    """Process all the deb source directories in a request."""
    components: list[Component] = []

    for package in request.deb_packages:
        path = request.source_dir.join_within_root(package.path)
        components.extend(
            _resolve_deb_project(
                path,
                request.output_dir,
                binary_filter=package.binary,
            )
        )

    annotations = []
    if backend_annotation := create_backend_annotation(components, "x-deb"):
        annotations.append(backend_annotation)
    return RequestOutput.from_obj_list(
        components=components,
        environment_variables=[],
        project_files=[],
        annotations=annotations,
    )


def _resolve_deb_project(
    source_dir: RootedPath,
    output_dir: RootedPath,
    binary_filter: DebBinaryFilters | None = None,
) -> list[Component]:
    """Process a request for a single DEB source directory.

    Process the input lockfile, fetch packages and generate SBOM.
    """
    # Check the availability of the input lockfile.
    if not source_dir.join_within_root(DEFAULT_LOCKFILE_NAME).path.exists():
        raise LockfileNotFound(
            files=source_dir.join_within_root(DEFAULT_LOCKFILE_NAME).path,
        )

    lockfile_name = source_dir.join_within_root(DEFAULT_LOCKFILE_NAME)
    log.info(f"Reading DEB lockfile: {lockfile_name}")
    with open(lockfile_name) as f:
        try:
            yaml_content = yaml.safe_load(f)
        except yaml.YAMLError as e:
            log.error(str(e))
            raise InvalidLockfileFormat(
                lockfile_path=source_dir.join_within_root(DEFAULT_LOCKFILE_NAME).path,
                err_details=str(e),
                solution="Check correct 'yaml' syntax in the lockfile.",
            )

        log.debug("Validating lockfile.")
        try:
            debian_debs_lock = DebianDebsLock.model_validate(yaml_content)
        except ValidationError as e:
            loc = e.errors()[0]["loc"]
            msg = e.errors()[0]["msg"]
            raise InvalidLockfileFormat(
                lockfile_path=source_dir.join_within_root(DEFAULT_LOCKFILE_NAME).path,
                err_details=f"{loc}: {msg}",
            )

        package_dir = output_dir.join_within_root(DEFAULT_PACKAGE_DIR)
        arch_filter = DEBArchitectureFilter(binary_filter)
        metadata = _download(debian_debs_lock, package_dir.path, arch_filter)
        _verify_downloaded(metadata)

        lockfile_relative_path = source_dir.subpath_from_root / DEFAULT_LOCKFILE_NAME
        return _generate_sbom_components(
            metadata, lockfile_relative_path, debian_debs_lock.lockfileVendor
        )


def _download(
    lockfile: DebianDebsLock,
    output_dir: Path,
    binary_filter: DEBArchitectureFilter | None = None,
) -> dict[Path, Any]:
    """Download packages mentioned in the lockfile.

    Go through the parsed lockfile structure and find all .deb and source files.
    Create a metadata structure indexed by destination path used
    for later verification (size, checksum) after download.
    Prepare a list of files to be downloaded, and then download files.
    """
    if binary_filter is not None:
        arches_to_process = binary_filter.validate_and_filter(lockfile.arches)
    else:
        arches_to_process = lockfile.arches

    metadata: dict[Path, Any] = {}
    for arch in arches_to_process:
        log.info(f"Downloading files for '{arch.arch}' architecture.")
        # files per URL for downloading packages & sources
        files: dict[str, str | PathLike[str]] = {}
        deb_iterator = zip(itertools.repeat("deb"), arch.packages)
        src_iterator = zip(itertools.repeat("source"), arch.source)

        for tag, pkg in itertools.chain(deb_iterator, src_iterator):
            repoid = pkg.repoid
            if not repoid:
                if tag == "deb":
                    repoid = lockfile.generated_repoid
                else:
                    repoid = lockfile.generated_source_repoid

            dest = output_dir.joinpath(arch.arch, repoid, Path(pkg.url).name)
            files[pkg.url] = str(dest)
            metadata[dest] = {
                "repoid": pkg.repoid,
                "url": pkg.url,
                "size": pkg.size,
                "checksum": pkg.checksum,
            }
            Path.mkdir(dest.parent, parents=True, exist_ok=True)

        asyncio.run(
            async_download_files(
                files,
                get_config().runtime.concurrency_limit,
            )
        )
    return metadata


def _verify_downloaded(metadata: dict[Path, Any]) -> None:
    """Use metadata structure with file sizes and checksums for verification \
    of downloaded packages and sources."""
    log.debug("Verification of downloaded files has started.")

    def raise_exception(filename: Path, message: str) -> None:
        raise ChecksumVerificationFailed(
            filename=filename,
            solution=(
                f"{message}."
                "Check the source of the data or check the corresponding metadata "
                "in the lockfile (size, checksum)."
            ),
        )

    # check file size and checksum of downloaded files
    for file_path, file_metadata in metadata.items():
        # size is optional
        if file_metadata["size"] is not None:
            if file_path.stat().st_size != file_metadata["size"]:
                raise_exception(
                    file_path, f"Unexpected file size of '{file_path}' != {file_metadata['size']}"
                )

        # checksum is optional
        if file_metadata["checksum"] is not None:
            alg, digest = file_metadata["checksum"].split(":")
            method = getattr(hashlib, alg.lower(), None)
            if method is not None:
                h = method(usedforsecurity=False)
            else:
                raise_exception(
                    file_path, f"Unsupported hashing algorithm '{alg}' for '{file_path}'"
                )
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(READ_CHUNK), b""):
                    h.update(chunk)
            if digest != h.hexdigest():
                raise_exception(file_path, f"Unmatched checksum of '{file_path}' != '{digest}'")


def _is_deb_file(file_path: Path) -> bool:
    """Check if it's a .deb file."""
    return file_path.suffix == ".deb"


def _generate_sbom_components(
    files_metadata: dict[Path, Any],
    lockfile_path: Path,
    lockfile_vendor: str,
) -> list[Component]:
    """Generate SBOM components from downloaded .deb packages."""
    components = []
    for file_path, file_metadata in files_metadata.items():
        if not _is_deb_file(file_path):
            continue
        package = Package.from_filepath(file_path, file_metadata, lockfile_vendor)
        component = package.to_component(lockfile_path)
        components.append(component)
    return components


def inject_files_post(
    from_output_dir: Path,
    for_output_dir: Path,
    **kwargs: Any,  # noqa: ARG001
) -> None:
    """Run extra tasks for the DEB package manager (callback method) within `inject-files` cmd.

    Generates a Packages index file via dpkg-scanpackages and a sources.list
    so that APT can consume the prefetched .deb files offline.
    """
    package_dir = from_output_dir.joinpath(DEFAULT_PACKAGE_DIR)
    if not package_dir.exists():
        return

    for arch in package_dir.iterdir():
        if not arch.is_dir():
            continue
        for entry in arch.iterdir():
            if not entry.is_dir() or entry.name == "apt":
                continue
            _generate_packages_index(entry)

        _generate_sources_list(arch, for_output_dir)


def _generate_packages_index(repo_dir: Path) -> None:
    """Generate a Packages index file using dpkg-scanpackages."""
    log.info(f"Generating Packages index for: {repo_dir}")
    try:
        result = subprocess.run(
            ["dpkg-scanpackages", "--multiversion", "."],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
            cwd=str(repo_dir),
        )
        packages_path = repo_dir / "Packages"
        packages_path.write_text(result.stdout)
        log.debug("Packages index written to '%s'", packages_path)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        log.warning("Could not generate Packages index for '%s': %s", repo_dir, e)


def _generate_sources_list(arch_dir: Path, for_output_dir: Path) -> None:
    """Generate a sources.list file for APT offline usage."""
    apt_dir = arch_dir / "apt"
    apt_dir.mkdir(parents=True, exist_ok=True)

    sources_list_path = apt_dir / "sources.list"
    lines = []
    for entry in sorted(arch_dir.iterdir()):
        if not entry.is_dir() or entry.name == "apt":
            continue
        repoid = entry.name
        local_path = for_output_dir.joinpath(DEFAULT_PACKAGE_DIR, arch_dir.name, repoid)
        lines.append(f"deb [trusted=yes] file://{local_path} ./")

    if lines:
        if sources_list_path.exists():
            log.warning(f"Overwriting {sources_list_path}")
        else:
            log.info(f"Creating {sources_list_path}")
        sources_list_path.write_text("\n".join(lines) + "\n")
