"""
MITRE ATT&CK Technique Validator

Validates MITRE ATT&CK technique IDs against the official framework
"""
from typing import List


class MITREValidator:
    """
    Validates MITRE ATT&CK technique IDs

    Checks if technique IDs exist in the MITRE ATT&CK framework.
    Supports both parent techniques (T1234) and sub-techniques (T1234.567).
    """

    # Comprehensive set of MITRE ATT&CK techniques
    # In production, this should be loaded from official MITRE CTI repository
    # https://github.com/mitre/cti
    VALID_TECHNIQUES = {
        # Phishing (T1566)
        "T1566", "T1566.001", "T1566.002", "T1566.003",

        # Application Layer Protocol (T1071)
        "T1071", "T1071.001", "T1071.002", "T1071.003", "T1071.004",

        # Command and Scripting Interpreter (T1059)
        "T1059", "T1059.001", "T1059.002", "T1059.003", "T1059.004",
        "T1059.005", "T1059.006", "T1059.007", "T1059.008",

        # Data Encrypted for Impact (T1486)
        "T1486",

        # Exfiltration Over Alternative Protocol (T1048)
        "T1048", "T1048.001", "T1048.002", "T1048.003",

        # Exploit Public-Facing Application (T1190)
        "T1190",

        # Common malware/C2 techniques
        "T1095",  # Non-Application Layer Protocol
        "T1105",  # Ingress Tool Transfer
        "T1573",  # Encrypted Channel
        "T1041",  # Exfiltration Over C2 Channel

        # Credential Access
        "T1110",  # Brute Force
        "T1110.001", "T1110.002", "T1110.003", "T1110.004",
        "T1555",  # Credentials from Password Stores
        "T1555.001", "T1555.002", "T1555.003",

        # Execution
        "T1203",  # Exploitation for Client Execution
        "T1204",  # User Execution
        "T1204.001", "T1204.002", "T1204.003",

        # Persistence
        "T1547",  # Boot or Logon Autostart Execution
        "T1547.001", "T1547.002",
        "T1053",  # Scheduled Task/Job
        "T1053.001", "T1053.002", "T1053.003", "T1053.005",

        # Defense Evasion
        "T1027",  # Obfuscated Files or Information
        "T1027.001", "T1027.002", "T1027.003", "T1027.004", "T1027.005",
        "T1140",  # Deobfuscate/Decode Files or Information
        "T1562",  # Impair Defenses
        "T1562.001", "T1562.002", "T1562.003",

        # Discovery
        "T1018",  # Remote System Discovery
        "T1083",  # File and Directory Discovery
        "T1087",  # Account Discovery
        "T1087.001", "T1087.002",
        "T1057",  # Process Discovery

        # Lateral Movement
        "T1021",  # Remote Services
        "T1021.001", "T1021.002", "T1021.003", "T1021.004",
        "T1570",  # Lateral Tool Transfer

        # Collection
        "T1560",  # Archive Collected Data
        "T1560.001", "T1560.002", "T1560.003",
        "T1113",  # Screen Capture
        "T1005",  # Data from Local System

        # Impact
        "T1485",  # Data Destruction
        "T1490",  # Inhibit System Recovery
        "T1491",  # Defacement
        "T1491.001", "T1491.002",
    }

    @classmethod
    def validate(cls, technique_id: str) -> bool:
        """
        Validate if technique ID exists in MITRE ATT&CK framework

        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., "T1566", "T1566.001")

        Returns:
            True if technique ID is valid, False otherwise
        """
        if not technique_id or not isinstance(technique_id, str):
            return False

        # Check for exact match first
        if technique_id in cls.VALID_TECHNIQUES:
            return True

        # Check if it's a sub-technique and parent exists
        if '.' in technique_id:
            parent = technique_id.split('.')[0]
            return parent in cls.VALID_TECHNIQUES

        return False

    @classmethod
    def filter_valid(cls, technique_ids: List[str]) -> List[str]:
        """
        Filter list to only valid MITRE ATT&CK IDs

        Args:
            technique_ids: List of technique IDs to filter

        Returns:
            List containing only valid technique IDs, preserving order
        """
        return [tid for tid in technique_ids if cls.validate(tid)]
