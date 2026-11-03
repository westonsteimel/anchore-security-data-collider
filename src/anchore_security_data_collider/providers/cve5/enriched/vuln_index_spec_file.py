import logging
import os
import tomllib
from copy import deepcopy
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from packaging.utils import canonicalize_name

from anchore_security_data_collider.identifiers.anchore_id import parse as parse_anchore_id

if TYPE_CHECKING:
    from anchore_security_data_collider.identifiers.anchore_id import AnchoreId

def _construct_cpe(cpe: dict[str, str]) -> str:
    part = cpe.get("part", "a")
    vendor = cpe.get("vendor", "*")
    product = cpe.get("product", "*")
    edition = cpe.get("edition", "*")
    language = cpe.get("language", "*")
    software_edition = cpe.get("software_edition", "*")
    target_software = cpe.get("target_software", "*")
    target_hardware = cpe.get("target_hardware", "*")
    other = cpe.get("other", "*")
    return f"cpe:2.3:{part}:{vendor}:{product}:*:*:{edition}:{language}:{software_edition}:{target_software}:{target_hardware}:{other}"

@dataclass(frozen=False, slots=True)
class VulnIndexSpec:
    indexed_nvd_specs: dict[str, dict]
    curator: dict | None = None
    snapshot: dict | None = None

    def cve(self, cve_id: str) -> dict | None:
        return self.indexed_nvd_specs.get(cve_id)

@dataclass(frozen=False, slots=True)
class CVEReferenceIndex:
    url: str
    index: int
    value: dict

class VulnIndexSpecFileEnvelope:
    def __init__(self, anchore_id: AnchoreId | str, repo_root: str):
        self._logger = logging.getLogger("vuln-index-spec-file-envelope")

        if isinstance(anchore_id, str):
            anchore_id = parse_anchore_id(anchore_id)

        self._anchore_id = anchore_id
        self._repo_root = repo_root
        self._spec: VulnIndexSpec = None
        self.__load__()

    @property
    def anchore_id(self) -> AnchoreId:
        return self._anchore_id

    @property
    def spec(self) -> VulnIndexSpec:
        return self._spec

    def __load__(self):
        spec_file_path = self._anchore_id.filename(root=os.path.join(self._repo_root, "data"))
        self._logger.debug(f"{self._anchore_id!s}: loading from {spec_file_path}")
        if not os.path.exists(spec_file_path):
            self._logger.error(f"{spec_file_path} does not exist")
            raise ValueError(f"{spec_file_path} does not exist")

        with open(spec_file_path, "rb") as fp:
            spec_toml = tomllib.load(fp)

        vuln = spec_toml.get("vuln", {})
        anchore_id = vuln.get("id")

        if not anchore_id:
            raise ValueError(f"{self._anchore_id!s}:No Anchore identifier found in {spec_file_path}")

        if str(anchore_id) != str(self._anchore_id):
            raise ValueError(f"{self._anchore_id!s}: {anchore_id!s} from {spec_file_path} does not match expected")

        indexed = {}
        for v in vuln.get("providers", {}).get("nvd", []):
            cve_id = v["id"]
            indexed[cve_id] = v

        self._spec = VulnIndexSpec(
            indexed_nvd_specs=indexed,
            curator=spec_toml.get("curator"),
            snapshot=spec_toml.get("snapshot"),
        )

    def _to_cve_affected_records(  # noqa: C901, PLR0911, PLR0912, PLR0915
        self,
        record_type: str,
        r: dict,
        cve_id: str,
    ) -> tuple[list[dict] | None, set[str]]:
        cve5_affected = []
        patch_references = set()
        p = {
            "_index": r.get("_index", 999_999_999),
        }
        cve5_affected.append(p)
        collection_url = r.get("collection_url")
        if collection_url:
            p["collectionURL"] = collection_url

        vendor = r.get("vendor")
        if vendor:
            p["vendor"] = vendor

        product = r.get("product")
        if product:
            p["product"] = product

        p["defaultStatus"] = "unaffected"

        match record_type:
            case "docker":
                package_name = r.get("package_name")
                if not package_name:
                    self._logger.warning(f"{self._anchore_id!s}: unable to transform {cve_id} due to missing packageName")
                    return None
                if not collection_url or "docker.com" in collection_url or "docker.io" in collection_url:
                    p["packageURL"] = f"pkg:docker/{package_name}"
                    if collection_url:
                        p["collectionURL"] = "https://hub.docker.com"
                else:
                    p["packageURL"] = f"pkg:docker/{package_name}?repository_url={quote(collection_url)}"
                    p["collectionURL"] = collection_url

                p["packageName"] = package_name
            case "jenkins-plugin":
                group_id = r.get("group_id")
                if not group_id:
                    self._logger.warning(f"{self._anchore_id!s}: unable to transform {cve_id} due to missing group_id")
                    return None
                artifact_id = r.get("artifact_id")
                if not artifact_id:
                    self._logger.warning(f"{self._anchore_id!s}: unable to transform {cve_id} due to missing artifact_id")
                    return None
                repository_url = collection_url
                if collection_url == "https://plugins.jenkins.io":
                    repository_url = "https://repo.jenkins-ci.org/artifactory/releases"
                    p["collectionURL"] = repository_url
                p["packageName"] = f"{group_id}:{artifact_id}"
                p["packageURL"] = f"pkg:maven/{group_id}/{artifact_id}?repository_url={quote(repository_url)}"
            case "maven":
                group_id = r.get("group_id")
                if not group_id:
                    self._logger.warning(f"{self._anchore_id!s}: unable to transform {cve_id} due to missing group_id")
                    return None
                artifact_id = r.get("artifact_id")
                if not artifact_id:
                    self._logger.warning(f"{self._anchore_id!s}: unable to transform {cve_id} due to missing artifact_id")
                    return None
                if not collection_url or collection_url.startswith("https://repo.maven.apache.org/maven2"):
                    p["packageURL"] = f"pkg:maven/{group_id}/{artifact_id}"
                else:
                    p["packageURL"] = f"pkg:maven/{group_id}/{artifact_id}?repository_url={quote(collection_url)}"
                p["packageName"] = f"{group_id}:{artifact_id}"
            case "npm":
                package_name = r.get("package_name")
                if not package_name:
                    self._logger.warning(f"{self._anchore_id!s}: unable to transform {cve_id} due to missing packageName")
                    return None
                npmjs_repo = "://registry.npmjs.org" in collection_url or "://www.npmjs.com/" in collection_url or "://npmjs.com/" in collection_url  # noqa: E501
                purl_package_name = quote(package_name)
                if not collection_url or npmjs_repo:
                    p["packageURL"] = f"pkg:npm/{purl_package_name}"

                    if npmjs_repo:
                        p["collectionURL"] = "https://registry.npmjs.org"
                else:
                    p["packageURL"] = f"pkg:npm/{purl_package_name}?repository_url={quote(collection_url)}"
                    p["collectionURL"] = collection_url
                p["packageName"] = package_name
            case "python":
                package_name = r.get("package_name")
                if package_name:
                    package_name = canonicalize_name(package_name)
                if not package_name:
                    self._logger.warning(f"{self._anchore_id!s}: unable to transform {cve_id} due to missing packageName")
                    return None
                if not collection_url or "://pypi.org" in collection_url or "://pypi.python.org" in collection_url:
                    p["packageURL"] = f"pkg:pypi/{package_name}"

                    if "://pypi.org" in collection_url or "://pypi.python.org" in collection_url:
                        p["collectionURL"] = "https://pypi.org"
                else:
                    p["packageURL"] = f"pkg:pypi/{package_name}?repository_url={quote(collection_url)}"
                    p["collectionURL"] = collection_url

                p["packageName"] = package_name
            case "vscode-extension":
                publisher = r["publisher"]
                extension_name = r["extension_name"]
                collection_url = r["collection_url"]

                if not collection_url or "://marketplace.visualstudio.com" in collection_url:
                    p["packageURL"] = f"pkg:vscode-extension/{publisher}/{extension_name}"

                    if collection_url:
                        p["collectionURL"] = collection_url
                else:
                    p["packageURL"] = f"pkg:vscode-extension/{publisher}/{extension_name}?repository_url={quote(collection_url)}"
                    p["collectionURL"] = collection_url

                p["packageName"] = f"{publisher}.{extension_name}"
                p["collectionURL"] = r["collection_url"]
            case "rust-crate":
                package_name = r.get("package_name")
                if not package_name:
                    self._logger.warning(f"{self._anchore_id!s}: unable to transform {cve_id} due to missing packageName")
                    return None
                if not collection_url or "://crates.io" in collection_url:
                    p["packageURL"] = f"pkg:cargo/{package_name}"

                    if "://crates.io" in collection_url:
                        p["collectionURL"] = "https://crates.io"
                else:
                    p["packageURL"] = f"pkg:cargo/{package_name}?repository_url={quote(collection_url)}"
                    p["collectionURL"] = collection_url

                p["packageName"] = package_name
            case "gem":
                package_name = r.get("package_name")
                if not package_name:
                    self._logger.warning(f"{self._anchore_id!s}: unable to transform {cve_id} due to missing packageName")
                    return None
                if not collection_url or "://rubygems.org" in collection_url:
                    p["packageURL"] = f"pkg:gem/{package_name}"

                    if "://rubygems.org" in collection_url:
                        p["collectionURL"] = "https://rubygems.org"
                else:
                    p["packageURL"] = f"pkg:gem/{package_name}?repository_url={quote(collection_url)}"
                    p["collectionURL"] = collection_url

                p["packageName"] = package_name
            case "php-composer":
                package_name = r.get("package_name")
                if not package_name:
                    self._logger.warning(f"{self._anchore_id!s}: unable to transform {cve_id} due to missing packageName")
                    return None
                if len(package_name.split("/", maxsplit=1)) != 2:
                    self._logger.warning(
                        f"{self._anchore_id!s}: unable to transform {cve_id} due to unlikely php-composer package name {package_name}",
                    )
                    return None
                if not collection_url or "://packagist.org" in collection_url:
                    p["packageURL"] = f"pkg:composer/{package_name}"

                    if "://packagist.org" in collection_url:
                        p["collectionURL"] = "https://packagist.org"
                else:
                    p["packageURL"] = f"pkg:composer/{package_name}?repository_url={quote(collection_url)}"
                    p["collectionURL"] = collection_url

                p["packageName"] = package_name
            case "cve5":
                cpes = r.get("cpe")
                if not cpes:
                    return None

                package_name = r.get("package_name")
                collection_url = r.get("collection_url")
                if package_name and collection_url:
                    p["packageName"] = package_name
                    p["collectionURL"] = collection_url

                if collection_url and collection_url.startswith("https://github.com") and package_name:
                    components = package_name.split("/")
                    if len(components) == 2:
                        p["packageURL"] = f"pkg:github/{package_name}"
            case _:
                # TODO: Handle other package types
                self._logger.warning(f"{self._anchore_id!s}: Skipping unimplemented product record type: {record_type}")
                return None

        source = r.get("source")
        github_repo: str | None = None
        if source:
            p["repo"] = source[0]["url"]

            for s in source:
                s_url = s["url"]
                if s_url.startswith("https://github.com"):
                    github_repo = s_url.strip("/")
                    break

        platforms = r.get("platforms")
        if platforms:
            p["platforms"] = platforms

        modules = r.get("modules")
        if modules:
            p["modules"] = modules

        program_files = r.get("program_files")
        if program_files:
            p["programFiles"] = program_files

        program_routines = r.get("program_routines")
        if program_routines:
            p["programRoutines"] = program_routines

        cpes = r.get("cpe")
        if cpes:
            p["cpes"] = []
            for cpe in cpes:
                p["cpes"].append(_construct_cpe(cpe))

        versions: list[dict[str, Any]] = []
        affected = r.get("affected", [])

        if affected:
            for affected_record in affected:
                a = affected_record["version"]
                v = {
                    "_index": affected_record.get("_index", 999_999_999),
                    "status": "affected",
                }
                less_than = a.get("less_than")
                less_than_or_equal = a.get("less_than_or_equal")
                start_inclusive = a.get("greater_than_or_equal")
                version = a.get("equals")
                scheme = a.get("scheme")

                # TODO: add an unaffected package entry for each remediation
                if less_than:
                    v["lessThan"] = less_than

                if less_than_or_equal:
                    v["lessThanOrEqual"] = less_than_or_equal

                if start_inclusive:
                    v["version"] = start_inclusive

                if version:
                    v["version"] = version

                if (less_than_or_equal or less_than) and not start_inclusive:
                    v["version"] = "0"

                if start_inclusive and not less_than_or_equal and not less_than:
                    v["lessThanOrEqual"] = "*"

                if scheme:
                    v["versionType"] = scheme

                versions.append(v)

                for remediation in affected_record.get("remediation", []):
                    remediated_version = remediation.get("version")
                    if remediated_version:
                        if "changes" not in v:
                            v["changes"] = []

                        v["changes"].append({
                            "at": remediated_version,
                            "status": "unaffected",
                        })

                    for patch in remediation.get("patch", []):
                        commit = patch.get("commit")
                        if commit:
                            if commit.startswith("https://"):
                                patch_references.add(commit)
                            # TODO: support rendering of URLs for other sources (once we have any data populated for them)
                            elif github_repo:
                                patch_references.add(f"{github_repo}/commit/{commit}")

                        pr = patch.get("pr")
                        if pr:
                            if pr.startswith("https://"):
                                patch_references.add(pr)
                            # TODO: support rendering of URLs for other sources (once we have any data populated for them)
                            elif github_repo:
                                patch_references.add(f"{github_repo}/pull/{pr}")

        unaffected = r.get("unaffected", [])
        if unaffected:
            for unaffected_record in unaffected:
                a = unaffected_record["version"]
                v = {
                    "_index": unaffected_record.get("_index", 999_999_999),
                    "status": "unaffected",
                }
                less_than = a.get("less_than")
                less_than_or_equal = a.get("less_than_or_equal")
                start_inclusive = a.get("greater_than_or_equal")
                version = a.get("equals")
                scheme = a.get("scheme")

                if less_than:
                    v["lessThan"] = less_than

                if less_than_or_equal:
                    v["lessThanOrEqual"] = less_than_or_equal

                if start_inclusive:
                    v["version"] = start_inclusive

                if version:
                    v["version"] = version

                if (less_than_or_equal or less_than) and not start_inclusive:
                    v["version"] = "0"

                if start_inclusive and not less_than_or_equal and not less_than:
                    v["lessThanOrEqual"] = "*"

                if scheme:
                    v["versionType"] = scheme

                versions.append(v)

        investigating = r.get("investigating", [])
        if investigating:
            for investigating_record in investigating:
                a = investigating_record["version"]
                v = {
                    "_index": investigating_record.get("_index", 999_999_999),
                    "status": "unknown",
                }
                less_than = a.get("less_than")
                less_than_or_equal = a.get("less_than_or_equal")
                start_inclusive = a.get("greater_than_or_equal")
                version = a.get("equals")
                scheme = a.get("scheme")

                if less_than:
                    v["lessThan"] = less_than

                if less_than_or_equal:
                    v["lessThanOrEqual"] = less_than_or_equal

                if start_inclusive:
                    v["version"] = start_inclusive

                if version:
                    v["version"] = version

                if (less_than_or_equal or less_than) and not start_inclusive:
                    v["version"] = "0"

                if start_inclusive and not less_than_or_equal and not less_than:
                    v["lessThanOrEqual"] = "*"

                if scheme:
                    v["versionType"] = scheme

                versions.append(v)

        if versions:
            versions = sorted(versions, key=lambda v: v["_index"])
            for version in versions:
                del version["_index"]
            p["versions"] = versions

        # Create the additional jenkins-plugin registry record
        if record_type == "jenkins-plugin":
            p2 = deepcopy(p)
            p2["collectionURL"] = r["registry"]
            p2["packageName"] = r["plugin_name"]
            if "packageURL" in p2:
                del p2["packageURL"]
            cve5_affected.append(p2)

        return cve5_affected, patch_references

    def to_cve_container_fragment(  # noqa: C901, PLR0911, PLR0912, PLR0915
        self,
        cve_id: str,
        initial_container: dict | None = None,
        allowed_product_types: set[str] | None = None,
    ) -> dict | None:
        nvd_spec = self._spec.cve(cve_id=cve_id)

        if not nvd_spec:
            self._logger.warning(f"{self._anchore_id!s}: no spec for {cve_id}")
            return None

        fragment = {}
        if initial_container:
            fragment = initial_container

        disputed = nvd_spec.get("disputed")
        if disputed:
            mark_disputed = disputed.get("override", False)
            if mark_disputed:
                if "tags" not in fragment:
                    fragment["tags"] = []

                if "disputed" not in fragment["tags"]:
                    fragment["tags"].append("disputed")

        rejected = nvd_spec.get("rejection")
        if rejected:
            return None

        suppression = nvd_spec.get("suppression")
        if suppression:
            ignore = suppression["override"]
            if ignore:
                if "tags" not in fragment:
                    fragment["tags"] = []

                if "suppressed" not in fragment["tags"]:
                    fragment["tags"].append("x_anchore_suppressed")

                    if "x_anchore" not in fragment:
                        fragment["x_anchore"] = {}

                    fragment["x_anchore"]["suppression"] = {
                        "enabled": True,
                        "reason": suppression["reason"],
                    }

        # TODO: eventually we will need to resolve the entire set of references from the aggregate view once we have that
        # so that we can process drop, override, etc.  For now we expect everything to be merge (previously add), so will
        # only consider those keys.
        references = nvd_spec.get("references", {}).get("merge")
        if not references:
            references = nvd_spec.get("references", {}).get("add")

        cve5_references = []
        if references:
            for r in references:
                cve5_references.append(
                    {
                        "url": r["url"],
                    },
                )

        cve5_affected: list[dict[str, Any]] = []
        # TODO: eventually need to support all of the new add/remove logic
        overrides = nvd_spec.get("products", {}).get("override", {})
        patch_references: set[str] = set()
        if overrides:
            for record_type, records in overrides.items():
                if allowed_product_types and record_type not in allowed_product_types:
                    self._logger.debug(f"{self._anchore_id!s}: skipping {cve_id} because product_type {record_type} was not in the filter set")
                    return None

                for r in records:
                    cve5_local_records, patch_url_set = self._to_cve_affected_records(record_type, r, cve_id)
                    if not cve5_local_records:
                        return None

                    cve5_affected.extend(cve5_local_records)
                    if patch_url_set:
                        patch_references.update(patch_url_set)

        for patch_ref in patch_references:
            cve5_references.append(
                {
                    "url": patch_ref,
                    "tags": ["patch"],
                },
            )

        next_index = 0
        if cve5_references:
            existing: dict[str, CVEReferenceIndex] = {}
            for index, ref in enumerate(initial_container.get("references", [])):
                url = ref["url"]
                if url not in existing:
                    existing[url] = CVEReferenceIndex(url=url, index=index, value=ref)
                elif "tags" not in existing[url].value:
                    existing[url].value["tags"] = ref.get("tags", [])
                else:
                    for t in ref.get("tags", []):
                        if t not in existing[url].value["tags"]:
                            existing[url].value["tags"].append(t)
                next_index += 1

            for ref in cve5_references:
                url = ref["url"]
                ex = existing.get(url)
                if not ex:
                    existing[url] = CVEReferenceIndex(url=url, index=next_index, value=ref)
                    next_index += 1
                elif "tags" not in existing[url].value:
                    existing[url].value["tags"] = ref.get("tags", [])
                else:
                    for t in ref.get("tags", []):
                        if t not in existing[url].value["tags"]:
                            existing[url].value["tags"].append(t)

            ordered = []
            for ref in sorted(existing.values(), key=lambda r: r.index):
                ordered.append(ref.value)

            fragment["references"] = ordered

        if cve5_affected:
            cve5_affected = sorted(cve5_affected, key=lambda a: a["_index"])
            for affected in cve5_affected:
                del affected["_index"]
            fragment["affected"] = cve5_affected

        return fragment
