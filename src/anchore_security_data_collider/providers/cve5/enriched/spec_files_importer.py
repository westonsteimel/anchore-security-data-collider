import json
import logging
import os
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from glob import iglob

import tomlkit

from anchore_security_data_collider.providers.cve5.enriched.config import EnrichedDatasetConfig
from anchore_security_data_collider.providers.cve5.enriched.vuln_index_spec_file import VulnIndexSpecFileEnvelope
from anchore_security_data_collider.providers.cve5.identifier import parse_identifier
from anchore_security_data_collider.utils import timer

# CNAs that will have data that isn't currently worth trying to automate imports
# Will currently print out a warning with the proposed change instead
manually_reconciled_cnas: set[str] = {
    "redhat",
}

@dataclass(frozen=True, slots=True)
class SpecFilesImporterConfig(EnrichedDatasetConfig):
    spec_files_repo_root: str

@dataclass(frozen=False, slots=True)
class CVEReferenceIndex:
    url: str
    index: int
    value: dict

class ProcessStatus(StrEnum):
    SKIPPED = "skipped"
    MODIFIED = "modified"
    UNCHANGED = "unchanged"

@dataclass(frozen=True, slots=True)
class SpecFilesImporterOptions:
    cves: list[str] | None = None
    anchore_ids: list[str] | None = None
    assigners: list[str] | None = None
    product_types: list[str] | None = None
    batch_size: int | None = None
    set_import_date: bool = False

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

class SpecFilesImporter:
    def __init__(self, config: SpecFilesImporterConfig):
        self._logger = logging.getLogger("spec-files-importer")
        self._config = config
        self._data_path = os.path.join(self._config.enriched_repo_root, "data")

    def _ready(self) -> bool:
        if not os.path.exists(self._config.enriched_repo_root):
            return False

        return os.path.exists(self._config.spec_files_repo_root)

    def _process_nvd_spec(self, envelope: VulnIndexSpecFileEnvelope, cve_id: str, options: SpecFilesImporterOptions) -> ProcessStatus:  # noqa: C901, PLR0911, PLR0912, PLR0915
        nvd_spec = envelope.spec.cve(cve_id)
        if not nvd_spec:
            return ProcessStatus.SKIPPED

        cve_id_string = nvd_spec.get("id")
        if not cve_id_string:
            return ProcessStatus.SKIPPED

        cve_id = parse_identifier(cve_id_string)
        if not cve_id:
            self._logger.warning(f"Skipping {cve_id_string} due to error while parsing identifier")
            return ProcessStatus.SKIPPED

        cve5_fragment_path = cve_id.filename(self._data_path)
        if not os.path.exists(cve5_fragment_path):
            self._logger.warning(f"{cve_id!s}: Skipping because no base fragment found at {cve5_fragment_path}.  Ensure you have synced the control data first and merged to the enriched dataset")  # noqa: E501
            return ProcessStatus.SKIPPED

        with open(cve5_fragment_path) as fp:
            original_cve_record = json.load(fp)

        cve_metadata = original_cve_record.get("cveMetadata")
        if not cve_metadata:
            self._logger.warning(f"{cve_id!s}: Skipping because no cveMetadata section found at {cve5_fragment_path}")
            return ProcessStatus.SKIPPED

        cna: str = cve_metadata.get("assignerShortName")
        if not cna:
            self._logger.warning(f"{cve_id!s}: Skipping because assignerShortName not present in cveMetadata section for {cve5_fragment_path}")
            return ProcessStatus.SKIPPED

        revised_cve_record = deepcopy(original_cve_record)
        cna_container = revised_cve_record.get("containers", {}).get("cna")
        if not cna_container:
            self._logger.warning(f"{cve_id!s}: Skipping because no cna container section found for {cve5_fragment_path}")
            return ProcessStatus.SKIPPED

        cna_container_fragment = envelope.to_cve_container_fragment(str(cve_id), cna_container, options.product_types)

        if not cna_container_fragment:
            return ProcessStatus.SKIPPED

        revised_cve_record["containers"]["cna"] = cna_container_fragment

        if original_cve_record == revised_cve_record:
            return ProcessStatus.UNCHANGED

        if cna in manually_reconciled_cnas:
            self._logger.warning(f"{cve_id!s}: Manual reconciliation needed for {cve_id}, cna: {cna}")
            self._logger.warning(json.dumps(revised_cve_record, ensure_ascii=False, indent=2, sort_keys=True))
            return ProcessStatus.SKIPPED

        with open(cve5_fragment_path, "w") as fp:
            json.dump(revised_cve_record, fp, ensure_ascii=False, indent=2, sort_keys=True)
        return ProcessStatus.MODIFIED

    def set_import_date(self, spec_file: str):
        with open(spec_file) as f:
            self._logger.debug(f"Loading existing Anchore vulnerability data spec record for {spec_file}")
            document = tomlkit.load(f)
            if "curator" not in document:
                document.append("curator", tomlkit.table())

            if "anchore_cve5_enriched_import_date" not in document["curator"]:
                document["curator"]["anchore_cve5_enriched_import_date"] = datetime.now(tz=UTC)

        with open(spec_file, "w") as f:
            tomlkit.dump(document, f, sort_keys=False)

    def _process_spec_file(self, spec_file: str, options: SpecFilesImporterOptions) -> int:  # noqa: C901, PLR0912
        try:
            anchore_id = os.path.basename(spec_file).replace(".toml", "")
            envelope = VulnIndexSpecFileEnvelope(anchore_id=anchore_id, repo_root=self._config.spec_files_repo_root)

            if not envelope.spec and not envelope.spec.indexed_nvd_specs:
                logging.warning(f"Skipping {spec_file} with no CVE records")
                return 0

            if options.anchore_ids and str(envelope.anchore_id) not in options.anchore_ids:
                return 0

            if options.assigners or options.cves:
                if not envelope.spec.snapshot:
                    return 0

                found_cve = False
                found_assigner = False
                for cve_snapshot in envelope.spec.snapshot.get("cve5", []):
                    cve_id = cve_snapshot.get("id")
                    assigner = cve_snapshot.get("overview", {}).get("cna")

                    if options.assigners and assigner in options.assigners:
                        found_assigner = True
                        break

                    if options.cves and cve_id in options.cves:
                        found_cve = True
                        break

                if (options.cves and not found_cve) or (options.assigners and not found_assigner):
                    return 0

            updated_count = 0
            all_ingested = True
            for cve_id in envelope.spec.indexed_nvd_specs:
                status = self._process_nvd_spec(envelope, cve_id, options)
                if status == ProcessStatus.MODIFIED:
                    updated_count += 1

                if status == ProcessStatus.SKIPPED:
                    all_ingested = False

            if all_ingested and options.set_import_date:
                self.set_import_date(spec_file)

            return updated_count
        except Exception:
            self._logger.exception(f"Error processing {spec_file}")
            raise

    def _process_import(self, options: SpecFilesImporterOptions):
        # TODO: implement logic to filter by cve id and/or anchore id
        batched_changes = 0
        for spec_file in iglob(os.path.join(self._config.spec_files_repo_root, "data/**/ANCHORE-*.toml"), recursive=True):
            updated_count = self._process_spec_file(spec_file, options)
            batched_changes += updated_count

            if options.batch_size and batched_changes >= options.batch_size:
                self._logger.warning(f"Stopping for now as the update batch size of {options.batch_size} has been reached")
                break

    def import_(self, options: SpecFilesImporterOptions):
        if not self._ready():
            raise ValueError("Input data is not ready")

        with timer("importing improvements from vulnerability index spec files"):
            self._process_import(options)
