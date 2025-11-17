"""
Schema Validator Utility

Validates API responses and data against Pydantic schemas
Catches schema changes early and provides detailed error reporting
"""
from typing import List, Dict, Any, Type, Optional
from pydantic import BaseModel, ValidationError
import logging
from dataclasses import dataclass


@dataclass
class ValidationResult:
    """Result of schema validation"""
    is_valid: bool
    errors: List[str]
    validated_data: Optional[BaseModel]


class SchemaValidator:
    """
    Validates data against Pydantic schemas

    Provides detailed error reporting and batch validation support
    """

    def __init__(self, strict: bool = False):
        """
        Initialize schema validator

        Args:
            strict: If True, raise exception on validation failure
        """
        self.strict = strict
        self.logger = logging.getLogger(self.__class__.__name__)

    def validate(
        self,
        data: Dict[str, Any],
        schema: Type[BaseModel]
    ) -> ValidationResult:
        """
        Validate data against Pydantic schema

        Args:
            data: Data dictionary to validate
            schema: Pydantic model class to validate against

        Returns:
            ValidationResult with validation status and errors

        Raises:
            ValueError: If strict=True and validation fails
        """
        try:
            # Attempt to parse data with Pydantic schema
            validated = schema(**data)

            return ValidationResult(
                is_valid=True,
                errors=[],
                validated_data=validated
            )

        except ValidationError as e:
            # Extract error messages from Pydantic ValidationError
            error_messages = [
                f"{err['loc'][0] if err['loc'] else 'field'}: {err['msg']}"
                for err in e.errors()
            ]

            self.logger.warning(
                f"Schema validation failed for {schema.__name__}: {error_messages}"
            )

            if self.strict:
                raise ValueError(f"Validation failed: {error_messages}")

            return ValidationResult(
                is_valid=False,
                errors=error_messages,
                validated_data=None
            )

        except Exception as e:
            error_msg = f"Unexpected validation error: {str(e)}"
            self.logger.error(error_msg)

            if self.strict:
                raise ValueError(error_msg)

            return ValidationResult(
                is_valid=False,
                errors=[error_msg],
                validated_data=None
            )

    def validate_batch(
        self,
        data_list: List[Dict[str, Any]],
        schema: Type[BaseModel]
    ) -> List[ValidationResult]:
        """
        Validate batch of data items

        Args:
            data_list: List of data dictionaries
            schema: Pydantic model class

        Returns:
            List of ValidationResult objects
        """
        results = []

        for i, data in enumerate(data_list):
            result = self.validate(data, schema)
            results.append(result)

            if not result.is_valid:
                self.logger.debug(f"Item {i} failed validation: {result.errors}")

        return results

    def get_batch_summary(self, results: List[ValidationResult]) -> Dict[str, Any]:
        """
        Get summary statistics for batch validation

        Args:
            results: List of ValidationResult objects

        Returns:
            Dictionary with summary statistics
        """
        total = len(results)
        valid = sum(1 for r in results if r.is_valid)
        invalid = total - valid
        success_rate = (valid / total * 100) if total > 0 else 0

        return {
            'total': total,
            'valid': valid,
            'invalid': invalid,
            'success_rate': round(success_rate, 2)
        }

    def get_valid_items(
        self,
        results: List[ValidationResult]
    ) -> List[BaseModel]:
        """
        Extract only valid items from validation results

        Args:
            results: List of ValidationResult objects

        Returns:
            List of validated Pydantic models
        """
        return [
            r.validated_data
            for r in results
            if r.is_valid and r.validated_data is not None
        ]
