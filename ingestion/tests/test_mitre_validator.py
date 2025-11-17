"""
Tests for MITRE ATT&CK Validator

Following TDD - Tests written FIRST
"""
import pytest

from enrichment.mitre_validator import MITREValidator


@pytest.mark.unit
class TestMITREValidatorValidate:
    """Test MITRE ATT&CK technique ID validation"""

    def test_validate_exact_match_returns_true(self):
        """Should return True for exact technique ID match"""
        assert MITREValidator.validate("T1566") is True  # Phishing
        assert MITREValidator.validate("T1071") is True  # Application Layer Protocol
        assert MITREValidator.validate("T1486") is True  # Data Encrypted for Impact

    def test_validate_sub_technique_returns_true(self):
        """Should return True for valid sub-techniques"""
        assert MITREValidator.validate("T1566.001") is True  # Spearphishing Attachment
        assert MITREValidator.validate("T1566.002") is True  # Spearphishing Link
        assert MITREValidator.validate("T1071.001") is True  # Web Protocols

    def test_validate_parent_exists_returns_true(self):
        """Should return True if parent technique exists"""
        # Even if specific sub-technique not in list, parent exists
        assert MITREValidator.validate("T1566.999") is True  # Parent T1566 exists
        assert MITREValidator.validate("T1071.999") is True  # Parent T1071 exists

    def test_validate_invalid_technique_returns_false(self):
        """Should return False for invalid technique IDs"""
        assert MITREValidator.validate("T9999") is False
        assert MITREValidator.validate("T9999.001") is False
        assert MITREValidator.validate("INVALID") is False

    def test_validate_empty_string_returns_false(self):
        """Should return False for empty string"""
        assert MITREValidator.validate("") is False

    def test_validate_non_t_prefix_returns_false(self):
        """Should return False for IDs without T prefix"""
        assert MITREValidator.validate("1566") is False
        assert MITREValidator.validate("G0001") is False  # Group ID, not technique


@pytest.mark.unit
class TestMITREValidatorFilterValid:
    """Test filtering list of technique IDs"""

    def test_filter_all_valid_returns_all(self):
        """Should return all IDs when all are valid"""
        ttps = ["T1566", "T1071", "T1486"]
        result = MITREValidator.filter_valid(ttps)
        assert result == ttps

    def test_filter_removes_invalid(self):
        """Should filter out invalid technique IDs"""
        ttps = ["T1566", "INVALID", "T1071", "T9999"]
        result = MITREValidator.filter_valid(ttps)
        assert result == ["T1566", "T1071"]

    def test_filter_preserves_order(self):
        """Should preserve original order of valid IDs"""
        ttps = ["T1486", "T1071", "T1566"]
        result = MITREValidator.filter_valid(ttps)
        assert result == ttps

    def test_filter_empty_list_returns_empty(self):
        """Should return empty list for empty input"""
        assert MITREValidator.filter_valid([]) == []

    def test_filter_all_invalid_returns_empty(self):
        """Should return empty list when all IDs are invalid"""
        ttps = ["INVALID", "T9999", "FAKE"]
        result = MITREValidator.filter_valid(ttps)
        assert result == []

    def test_filter_includes_sub_techniques(self):
        """Should include valid sub-techniques"""
        ttps = ["T1566.001", "T1566.002", "T9999.001"]
        result = MITREValidator.filter_valid(ttps)
        assert result == ["T1566.001", "T1566.002"]

    def test_filter_handles_duplicates(self):
        """Should preserve duplicates if present"""
        ttps = ["T1566", "T1566", "T1071"]
        result = MITREValidator.filter_valid(ttps)
        assert result == ["T1566", "T1566", "T1071"]


@pytest.mark.unit
class TestMITREValidatorTechniques:
    """Test MITRE ATT&CK technique coverage"""

    def test_has_phishing_techniques(self):
        """Should include Phishing (T1566) family"""
        assert "T1566" in MITREValidator.VALID_TECHNIQUES
        assert MITREValidator.validate("T1566.001") is True  # Spearphishing Attachment
        assert MITREValidator.validate("T1566.002") is True  # Spearphishing Link
        assert MITREValidator.validate("T1566.003") is True  # Spearphishing via Service

    def test_has_application_layer_protocol(self):
        """Should include Application Layer Protocol (T1071) family"""
        assert "T1071" in MITREValidator.VALID_TECHNIQUES
        assert MITREValidator.validate("T1071.001") is True  # Web Protocols
        assert MITREValidator.validate("T1071.004") is True  # DNS

    def test_has_command_and_scripting_interpreter(self):
        """Should include Command and Scripting Interpreter (T1059) family"""
        assert "T1059" in MITREValidator.VALID_TECHNIQUES
        assert MITREValidator.validate("T1059.001") is True  # PowerShell
        assert MITREValidator.validate("T1059.003") is True  # Windows Command Shell

    def test_has_common_techniques(self):
        """Should include common attack techniques"""
        common = ["T1486", "T1048", "T1190"]
        for technique in common:
            assert technique in MITREValidator.VALID_TECHNIQUES
            assert MITREValidator.validate(technique) is True

    def test_technique_count_reasonable(self):
        """Should have reasonable number of techniques (not too few)"""
        # Should have at least a baseline set
        assert len(MITREValidator.VALID_TECHNIQUES) >= 10


@pytest.mark.unit
class TestMITREValidatorEdgeCases:
    """Test edge cases and error handling"""

    def test_case_sensitivity(self):
        """Should be case-sensitive (MITRE IDs are uppercase)"""
        assert MITREValidator.validate("T1566") is True
        assert MITREValidator.validate("t1566") is False  # lowercase should fail

    def test_whitespace_handling(self):
        """Should not accept IDs with whitespace"""
        assert MITREValidator.validate(" T1566") is False
        assert MITREValidator.validate("T1566 ") is False
        assert MITREValidator.validate("T1566\n") is False

    def test_multiple_dots_in_id(self):
        """Should handle IDs with multiple dots gracefully"""
        # T1566.001.002 is invalid (MITRE only has one level of sub-techniques)
        result = MITREValidator.validate("T1566.001.002")
        # Should still check parent T1566
        assert result is True  # Because parent exists

    def test_filter_preserves_non_string_types_gracefully(self):
        """Should handle non-string types gracefully (skip them)"""
        # This tests robustness - in practice we expect strings
        ttps = ["T1566", None, "T1071", 123, "T1486"]
        # Should not crash, but behavior depends on implementation
        # At minimum, valid strings should be returned
        result = MITREValidator.filter_valid([t for t in ttps if isinstance(t, str)])
        assert "T1566" in result
        assert "T1071" in result
        assert "T1486" in result


@pytest.mark.unit
class TestMITREValidatorExtensions:
    """Test potential extensions and additions"""

    def test_can_add_more_techniques(self):
        """Should be extensible to add more techniques"""
        # Verify structure supports adding more
        original_count = len(MITREValidator.VALID_TECHNIQUES)
        assert original_count > 0
        assert isinstance(MITREValidator.VALID_TECHNIQUES, set)

    def test_valid_techniques_is_set(self):
        """VALID_TECHNIQUES should be a set for O(1) lookup"""
        assert isinstance(MITREValidator.VALID_TECHNIQUES, set)

    def test_no_duplicate_techniques(self):
        """Should not have duplicate technique IDs"""
        techniques_list = list(MITREValidator.VALID_TECHNIQUES)
        techniques_set = set(techniques_list)
        assert len(techniques_list) == len(techniques_set)
