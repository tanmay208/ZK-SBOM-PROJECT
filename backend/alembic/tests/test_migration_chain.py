"""
Database-free regression tests for Alembic migration chain integrity (AUD-A-004).

Validates:
1. Exactly one migration head exists in the repository.
2. The current migration head is '014'.
3. The chain reaches base revision '001_initial'.
4. Every migration revision has a resolvable parent, except the base.
5. There are no duplicate revision identifiers, orphan branches, or merge cycles.
6. The entire revision sequence from 001_initial to 014 is strictly linear.
"""

from __future__ import annotations

import os
import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_ALEMBIC_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
_INI_PATH = os.path.abspath(os.path.join(_ALEMBIC_DIR, "..", "alembic.ini"))


@pytest.fixture
def script_directory() -> ScriptDirectory:
    """Construct an offline ScriptDirectory pointing to backend/alembic."""
    cfg = Config(_INI_PATH) if os.path.exists(_INI_PATH) else Config()
    cfg.set_main_option("script_location", _ALEMBIC_DIR)
    return ScriptDirectory.from_config(cfg)


class TestMigrationChainIntegrity:
    """Validate Alembic revision tree structure without database access."""

    def test_single_migration_head(self, script_directory: ScriptDirectory) -> None:
        """Requirement 1 & 2: Exactly one migration head exists, and it is '016'."""
        heads = script_directory.get_heads()
        assert len(heads) == 1, f"Expected exactly 1 migration head, got {len(heads)}: {heads}"
        assert heads[0] == "016", f"Expected current migration head to be '016', got '{heads[0]}'"

    def test_base_revision_is_initial_schema(self, script_directory: ScriptDirectory) -> None:
        """Requirement 3: The migration chain reaches base revision '001_initial'."""
        bases = script_directory.get_bases()
        assert len(bases) == 1, f"Expected exactly 1 base revision, got {len(bases)}: {bases}"
        assert bases[0] == "001_initial", f"Expected base revision to be '001_initial', got '{bases[0]}'"

    def test_revisions_are_unique_and_resolvable(self, script_directory: ScriptDirectory) -> None:
        """Requirement 4 & 5: No duplicate revision IDs, no unresolvable parents, no unintended branches."""
        revisions = list(script_directory.walk_revisions())
        rev_map = {rev.revision: rev for rev in revisions}

        # No duplicate revision identifiers
        assert len(revisions) == len(rev_map), "Duplicate revision identifiers detected in migration chain"

        # Exactly 16 revisions (001_initial through 016)
        assert len(revisions) == 16, f"Expected 16 revisions in chain, found {len(revisions)}"

        # Walk starts at current head
        assert revisions[0].revision == "016"

        # Every revision has a valid down_revision (except 001_initial)
        for rev in revisions:
            if rev.revision == "001_initial":
                assert rev.down_revision is None, "Base revision 001_initial must have down_revision=None"
            else:
                assert rev.down_revision is not None, f"Revision {rev.revision} has unexpected down_revision=None"
                assert isinstance(rev.down_revision, str), (
                    f"Revision {rev.revision} has non-string down_revision (branch/merge detected): {rev.down_revision}"
                )
                assert rev.down_revision in rev_map, (
                    f"Revision {rev.revision} refers to non-existent down_revision '{rev.down_revision}'"
                )

    def test_exact_linear_chain_sequence(self, script_directory: ScriptDirectory) -> None:
        """Verify the exact linear revision chain from head to base."""
        expected_sequence = [
            ("016", "015"),
            ("015", "014"),
            ("014", "013"),
            ("013", "012"),
            ("012", "011"),
            ("011", "010"),
            ("010", "009"),
            ("009", "008"),
            ("008", "007"),
            ("007", "006_add_proof_archive_hash"),
            ("006_add_proof_archive_hash", "005_add_topology_constraints"),
            ("005_add_topology_constraints", "004"),
            ("004", "003"),
            ("003", "002"),
            ("002", "001_initial"),
            ("001_initial", None),
        ]
        actual_sequence = [
            (rev.revision, rev.down_revision)
            for rev in script_directory.walk_revisions()
        ]
        assert actual_sequence == expected_sequence
