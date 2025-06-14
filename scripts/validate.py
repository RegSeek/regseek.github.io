#!/usr/bin/env python3
"""
RegSeek Validation System v2.0
Comprehensive validation of artifact YAML files against RegSeek standards
"""

import yaml
import sys
import re
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime

# Configuration Constants
VALID_CATEGORIES = [
    "program-execution", "browser-activity", "file-operations", "user-behaviour",
    "external-storage", "persistence-methods", "system-modifications", "network-infrastructure",
    "remote-access", "security-monitoring", "communication-apps", "virtualization", "authentication"
]

PRIORITY_CATEGORIES = [
    "program-execution", "browser-activity", "file-operations", "user-behaviour",
    "persistence-methods", "system-modifications", "network-infrastructure", "security-monitoring"
]

VALID_INVESTIGATION_TYPES = [
    # Investigation Phases
    "incident-response", "malware-analysis", "timeline-analysis", "behavioral-analysis", "insider-threat",
    # Attack Techniques
    "initial-access", "program-execution", "persistence-analysis", "privilege-escalation",
    "credential-theft", "lateral-movement", "remote-access", "data-exfiltration", "anti-forensics"
]

VALID_CRITICALITY_LEVELS = ["high", "medium", "low"]

VALID_REGISTRY_PREFIXES = ["HKLM\\", "HKCU\\", "HKCR\\", "HKU\\", "HKCC\\"]

VALID_REFERENCE_TYPES = ["official", "research", "blog", "tool"]

# Validation Rules
MIN_TITLE_LENGTH = 5
MIN_DESCRIPTION_LENGTH = 10
MIN_DETAILED_FIELD_LENGTH = 20
DATE_PATTERN = re.compile(r'^\d{4}-\d{2}-\d{2}$')
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
URL_PATTERN = re.compile(r'^https?://[^\s<>"{}|\\^`\[\]]+$')

class ValidationResult:
    """Store validation results"""
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.is_valid = True
        self.errors = []
        self.warnings = []
        self.recommendations = []
        
    def add_error(self, message: str):
        """Add validation error"""
        self.errors.append(message)
        self.is_valid = False
        
    def add_warning(self, message: str):
        """Add validation warning"""
        self.warnings.append(message)
        
    def add_recommendation(self, message: str):
        """Add recommendation for improvement"""
        self.recommendations.append(message)

class ArtifactValidator:
    """Comprehensive artifact validator"""
    
    def __init__(self):
        self.results = []
        
    def validate_required_fields(self, artifact: Dict[str, Any], result: ValidationResult):
        """Validate required top-level fields"""
        required_fields = {
            'title': str,
            'category': str,
            'description': str,
            'paths': (list, str)  # Can be list or string
        }
        
        for field, expected_type in required_fields.items():
            if field not in artifact:
                result.add_error(f"Missing required field: '{field}'")
                continue
                
            value = artifact[field]
            if not isinstance(value, expected_type):
                result.add_error(f"Field '{field}' must be {expected_type.__name__}, got {type(value).__name__}")
                continue
                
            # String length validation
            if isinstance(value, str):
                if field == 'title' and len(value) < MIN_TITLE_LENGTH:
                    result.add_error(f"Title must be at least {MIN_TITLE_LENGTH} characters, got {len(value)}")
                elif field == 'description' and len(value) < MIN_DESCRIPTION_LENGTH:
                    result.add_error(f"Description must be at least {MIN_DESCRIPTION_LENGTH} characters, got {len(value)}")
                elif not value.strip():
                    result.add_error(f"Field '{field}' cannot be empty")
    
    def validate_category(self, artifact: Dict[str, Any], result: ValidationResult):
        """Validate category field"""
        category = artifact.get('category')
        if not category:
            return
            
        if category not in VALID_CATEGORIES:
            result.add_error(f"Invalid category '{category}'. Must be one of: {', '.join(VALID_CATEGORIES)}")
            return
            
        # Check if it's a priority category
        if category in PRIORITY_CATEGORIES:
            result.add_recommendation(f"Category '{category}' is a priority category (appears in quick filters)")
    
    def validate_paths(self, artifact: Dict[str, Any], result: ValidationResult):
        """Validate registry paths"""
        paths = artifact.get('paths')
        if not paths:
            return
            
        # Convert single path to list
        if isinstance(paths, str):
            paths = [paths]
            
        if not isinstance(paths, list) or len(paths) == 0:
            result.add_error("Paths must be a non-empty list or string")
            return
            
        valid_hives = set()
        for i, path in enumerate(paths):
            if not isinstance(path, str):
                result.add_error(f"Path {i+1} must be a string, got {type(path).__name__}")
                continue
                
            if not path.strip():
                result.add_error(f"Path {i+1} cannot be empty")
                continue
                
            # Check registry path format
            path_valid = False
            for prefix in VALID_REGISTRY_PREFIXES:
                if path.startswith(prefix):
                    path_valid = True
                    valid_hives.add(prefix.rstrip('\\'))
                    break
                    
            if not path_valid:
                result.add_warning(f"Path may not be valid registry path: '{path}'")
                result.add_recommendation(f"Registry paths should start with: {', '.join(VALID_REGISTRY_PREFIXES)}")
        
        # Add recommendation about hive diversity
        if len(valid_hives) > 1:
            result.add_recommendation(f"Artifact spans multiple registry hives: {', '.join(sorted(valid_hives))}")
    
    def validate_details_section(self, artifact: Dict[str, Any], result: ValidationResult):
        """Validate details section (recommended)"""
        details = artifact.get('details', {})
        
        if not details:
            result.add_warning("Missing 'details' section (recommended)")
            return
            
        # Check for detailed explanations
        detail_fields = {
            'what': 'explanation of what Windows stores',
            'forensic_value': 'forensic significance explanation',
            'structure': 'data format and structure description'
        }
        
        for field, description in detail_fields.items():
            value = details.get(field)
            if not value:
                result.add_warning(f"Missing details.{field} ({description})")
            elif isinstance(value, str) and len(value.strip()) < MIN_DETAILED_FIELD_LENGTH:
                result.add_warning(f"details.{field} should be more detailed (at least {MIN_DETAILED_FIELD_LENGTH} characters)")
        
        # Check examples
        examples = details.get('examples')
        if not examples:
            result.add_warning("Missing details.examples (recommended)")
        elif isinstance(examples, list) and len(examples) == 0:
            result.add_warning("Examples list is empty")
        elif not isinstance(examples, list):
            result.add_warning("Examples should be a list of strings")
        
        # Check tools
        tools = details.get('tools')
        if not tools:
            result.add_warning("Missing details.tools (recommended)")
        elif isinstance(tools, list):
            self.validate_tools(tools, result)
        else:
            result.add_warning("Tools should be a list")
    
    def validate_tools(self, tools: List[Any], result: ValidationResult):
        """Validate tools list"""
        if len(tools) == 0:
            result.add_warning("Tools list is empty")
            return
            
        for i, tool in enumerate(tools):
            if not isinstance(tool, dict):
                result.add_warning(f"Tool {i+1} should be an object with 'name' field")
                continue
                
            if 'name' not in tool:
                result.add_error(f"Tool {i+1} missing required 'name' field")
                continue
                
            name = tool['name']
            if not isinstance(name, str) or not name.strip():
                result.add_error(f"Tool {i+1} name must be a non-empty string")
                continue
                
            # Check for URL (recommended)
            if 'url' not in tool:
                result.add_recommendation(f"Tool '{name}' missing URL (recommended)")
            else:
                url = tool['url']
                if not isinstance(url, str) or not URL_PATTERN.match(url):
                    result.add_warning(f"Tool '{name}' has invalid URL format")
    
    def validate_metadata_section(self, artifact: Dict[str, Any], result: ValidationResult):
        """Validate metadata section"""
        metadata = artifact.get('metadata', {})
        
        if not metadata:
            result.add_warning("Missing 'metadata' section (recommended)")
            return
        
        # Criticality validation
        criticality = metadata.get('criticality')
        if not criticality:
            result.add_recommendation("Missing metadata.criticality (recommended)")
        elif criticality not in VALID_CRITICALITY_LEVELS:
            result.add_error(f"Invalid criticality '{criticality}'. Must be one of: {', '.join(VALID_CRITICALITY_LEVELS)}")
        
        # Investigation types validation
        inv_types = metadata.get('investigation_types', [])
        if not inv_types:
            result.add_recommendation("Missing metadata.investigation_types (recommended)")
        elif isinstance(inv_types, list):
            invalid_types = [t for t in inv_types if t not in VALID_INVESTIGATION_TYPES]
            if invalid_types:
                result.add_error(f"Invalid investigation types: {', '.join(invalid_types)}")
                result.add_error(f"Valid types: {', '.join(VALID_INVESTIGATION_TYPES)}")
        else:
            result.add_error("investigation_types must be a list")
        
        # Windows versions
        win_versions = metadata.get('windows_versions')
        if not win_versions:
            result.add_recommendation("Missing metadata.windows_versions (recommended)")
        elif not isinstance(win_versions, list):
            result.add_warning("windows_versions should be a list")
        
        # References validation
        references = metadata.get('references', [])
        if isinstance(references, list):
            self.validate_references(references, result)
        
        # Date fields validation
        date_fields = ['introduced', 'deprecated']
        for field in date_fields:
            date_value = metadata.get(field)
            if date_value and not DATE_PATTERN.match(str(date_value)):
                result.add_warning(f"metadata.{field} should be in YYYY-MM-DD format")
    
    def validate_references(self, references: List[Any], result: ValidationResult):
        """Validate references list"""
        for i, ref in enumerate(references):
            if not isinstance(ref, dict):
                result.add_warning(f"Reference {i+1} should be an object")
                continue
                
            if 'title' not in ref:
                result.add_error(f"Reference {i+1} missing required 'title' field")
                continue
                
            # Check URL format
            if 'url' in ref:
                url = ref['url']
                if not isinstance(url, str) or not URL_PATTERN.match(url):
                    result.add_warning(f"Reference {i+1} has invalid URL format")
            
            # Check reference type
            ref_type = ref.get('type')
            if ref_type and ref_type not in VALID_REFERENCE_TYPES:
                result.add_warning(f"Reference {i+1} invalid type '{ref_type}'. Valid types: {', '.join(VALID_REFERENCE_TYPES)}")
    
    def validate_author_section(self, artifact: Dict[str, Any], result: ValidationResult):
        """Validate author section"""
        author = artifact.get('author')
        
        if not author:
            result.add_recommendation("Missing 'author' section (recommended for attribution)")
            return
            
        if not isinstance(author, dict):
            result.add_warning("Author should be an object with name, contact info")
            return
            
        if 'name' not in author:
            result.add_warning("Author missing 'name' field")
        elif not isinstance(author['name'], str) or not author['name'].strip():
            result.add_warning("Author name should be a non-empty string")
        
        # Email validation
        email = author.get('email')
        if email and not EMAIL_PATTERN.match(email):
            result.add_warning("Author email format appears invalid")
    
    def validate_contribution_section(self, artifact: Dict[str, Any], result: ValidationResult):
        """Validate contribution section"""
        contribution = artifact.get('contribution')
        
        if not contribution:
            result.add_recommendation("Missing 'contribution' section (recommended for tracking)")
            return
            
        if not isinstance(contribution, dict):
            result.add_warning("Contribution should be an object")
            return
            
        # Date validation
        date_fields = ['date_added', 'last_updated']
        for field in date_fields:
            date_value = contribution.get(field)
            if date_value and not DATE_PATTERN.match(str(date_value)):
                result.add_warning(f"contribution.{field} should be in YYYY-MM-DD format")
    
    def validate_anti_checklist_methodology(self, artifact: Dict[str, Any], result: ValidationResult):
        """Validate anti-checklist methodology sections (CRITICAL)"""
        # Limitations section
        limitations = artifact.get('limitations')
        if not limitations:
            result.add_error("CRITICAL: Missing 'limitations' section (anti-checklist methodology)")
            result.add_error("Must specify what this artifact CANNOT determine or prove")
        elif isinstance(limitations, list):
            if len(limitations) == 0:
                result.add_warning("Limitations list is empty")
            else:
                result.add_recommendation(f"Good: {len(limitations)} limitation(s) specified")
        else:
            result.add_warning("Limitations should be a list of strings")
        
        # Correlation section
        correlation = artifact.get('correlation')
        if not correlation:
            result.add_error("CRITICAL: Missing 'correlation' section (anti-checklist methodology)")
            result.add_error("Must specify required evidence for definitive conclusions")
        elif isinstance(correlation, dict):
            required = correlation.get('required_for_definitive_conclusions')
            strengthens = correlation.get('strengthens_evidence')
            
            if not required and not strengthens:
                result.add_warning("Correlation section empty - should specify required evidence")
            else:
                result.add_recommendation("Good: Correlation requirements specified")
        else:
            result.add_warning("Correlation should be an object with required/strengthens fields")
    
    def validate_file(self, file_path: Path) -> ValidationResult:
        """Validate a single artifact file"""
        result = ValidationResult(str(file_path))
        
        try:
            # Load YAML
            with open(file_path, 'r', encoding='utf-8') as f:
                artifact = yaml.safe_load(f)
                
            if not artifact:
                result.add_error("File is empty or contains invalid YAML")
                return result
                
            if not isinstance(artifact, dict):
                result.add_error("Root element must be a YAML object/dictionary")
                return result
            
            # Run all validations
            self.validate_required_fields(artifact, result)
            self.validate_category(artifact, result)
            self.validate_paths(artifact, result)
            self.validate_details_section(artifact, result)
            self.validate_metadata_section(artifact, result)
            self.validate_author_section(artifact, result)
            self.validate_contribution_section(artifact, result)
            self.validate_anti_checklist_methodology(artifact, result)
            
        except yaml.YAMLError as e:
            result.add_error(f"YAML parsing error: {e}")
        except Exception as e:
            result.add_error(f"Unexpected error: {e}")
            
        return result
    
    def validate_directory(self, artifacts_dir: Path = None) -> List[ValidationResult]:
        """Validate all artifacts in directory"""
        if artifacts_dir is None:
            artifacts_dir = Path("artifacts")
            
        if not artifacts_dir.exists():
            result = ValidationResult(str(artifacts_dir))
            result.add_error("Artifacts directory not found")
            return [result]
        
        results = []
        
        for category_dir in artifacts_dir.iterdir():
            if not category_dir.is_dir() or category_dir.name.startswith('_'):
                continue
                
            for artifact_file in category_dir.glob("*.yml"):
                if artifact_file.name.startswith('_'):
                    continue
                    
                result = self.validate_file(artifact_file)
                results.append(result)
        
        return results

def print_validation_summary(results: List[ValidationResult]):
    """Print comprehensive validation summary"""
    total_files = len(results)
    valid_files = sum(1 for r in results if r.is_valid)
    invalid_files = total_files - valid_files
    total_errors = sum(len(r.errors) for r in results)
    total_warnings = sum(len(r.warnings) for r in results)
    total_recommendations = sum(len(r.recommendations) for r in results)
    
    print("\n" + "=" * 70)
    print(" VALIDATION SUMMARY")
    print("=" * 70)
    
    # Overall stats
    print(f" STATISTICS:")
    print(f"   Files validated: {total_files}")
    print(f"   Valid: {valid_files}")
    print(f"   Invalid: {invalid_files}")
    print(f"   Total errors: {total_errors}")
    print(f"   Total warnings: {total_warnings}")
    print(f"   Total recommendations: {total_recommendations}")
    
    if total_files > 0:
        success_rate = round((valid_files / total_files) * 100, 1)
        print(f"   Success rate: {success_rate}%")
    
    # Categories
    categories = {}
    for result in results:
        if result.is_valid:
            # Extract category from path
            path_parts = Path(result.file_path).parts
            if len(path_parts) >= 2:
                category = path_parts[-2]  # Parent directory name
                categories[category] = categories.get(category, 0) + 1
    
    if categories:
        print(f"\n VALID ARTIFACTS BY CATEGORY:")
        for category, count in sorted(categories.items()):
            priority_marker = "⭐" if category in PRIORITY_CATEGORIES else "  "
            print(f"   {priority_marker} {category}: {count}")
    
    # Critical issues (anti-checklist methodology)
    critical_issues = []
    for result in results:
        for error in result.errors:
            if "CRITICAL" in error:
                critical_issues.append(f"{Path(result.file_path).name}: {error}")
    
    if critical_issues:
        print(f"\n CRITICAL ISSUES (Anti-Checklist Methodology):")
        for issue in critical_issues[:10]:  # Show first 10
            print(f"   • {issue}")
        if len(critical_issues) > 10:
            print(f"   ... and {len(critical_issues) - 10} more critical issues")
    
    # Most common warnings
    warning_counts = {}
    for result in results:
        for warning in result.warnings:
            # Extract warning type
            warning_type = warning.split('(')[0].strip()
            warning_counts[warning_type] = warning_counts.get(warning_type, 0) + 1
    
    if warning_counts:
        print(f"\n  COMMON WARNINGS:")
        sorted_warnings = sorted(warning_counts.items(), key=lambda x: x[1], reverse=True)
        for warning_type, count in sorted_warnings[:5]:
            print(f"   • {warning_type}: {count} files")

def print_file_results(results: List[ValidationResult], show_all: bool = False):
    """Print individual file validation results"""
    if not results:
        return
        
    print("\n" + "=" * 70)
    print(" FILE VALIDATION RESULTS")
    print("=" * 70)
    
    # Group by status
    valid_results = [r for r in results if r.is_valid]
    invalid_results = [r for r in results if not r.is_valid]
    
    # Show invalid files first
    if invalid_results:
        print(f"\n INVALID FILES ({len(invalid_results)}):")
        for result in invalid_results:
            file_name = Path(result.file_path).name
            print(f"\n   {file_name}")
            
            for error in result.errors:
                print(f"      {error}")
                
            if result.warnings:
                for warning in result.warnings[:3]:  # Limit warnings for invalid files
                    print(f"       {warning}")
                if len(result.warnings) > 3:
                    print(f"       ... and {len(result.warnings) - 3} more warnings")
    
    # Show valid files (summary or detailed)
    if valid_results:
        if show_all:
            print(f"\n VALID FILES ({len(valid_results)}):")
            for result in valid_results:
                file_name = Path(result.file_path).name
                issue_count = len(result.warnings) + len(result.recommendations)
                
                if issue_count == 0:
                    print(f"    {file_name} - Perfect!")
                else:
                    print(f"    {file_name} - {len(result.warnings)} warnings, {len(result.recommendations)} recommendations")
                    
                    for warning in result.warnings:
                        print(f"       {warning}")
                        
                    for rec in result.recommendations:
                        print(f"      {rec}")
        else:
            print(f"\n VALID FILES: {len(valid_results)} files passed validation")
            perfect_files = [r for r in valid_results if len(r.warnings) == 0 and len(r.recommendations) == 0]
            if perfect_files:
                print(f"   {len(perfect_files)} files are perfect (no warnings or recommendations)")

def main():
    """Main validation function"""
    print(" RegSeek Validation System v2.0")
    print("=" * 70)
    
    # Parse command line arguments
    show_detailed = '--detailed' in sys.argv or '-d' in sys.argv
    file_path = None
    
    # Check for specific file argument
    for arg in sys.argv[1:]:
        if not arg.startswith('-') and arg.endswith('.yml'):
            file_path = Path(arg)
            break
    
    # Initialize validator
    validator = ArtifactValidator()
    
    if file_path:
        # Validate single file
        if not file_path.exists():
            print(f" File not found: {file_path}")
            return 1
            
        print(f" Validating: {file_path}")
        result = validator.validate_file(file_path)
        results = [result]
        show_detailed = True  # Always show details for single file
    else:
        # Validate all files
        print(" Validating all artifacts...")
        results = validator.validate_directory()
    
    # Print results
    print_file_results(results, show_detailed)
    print_validation_summary(results)
    
    # Final status
    invalid_count = sum(1 for r in results if not r.is_valid)
    critical_count = sum(1 for r in results for e in r.errors if "CRITICAL" in e)
    
    print("\n" + "=" * 70)
    if invalid_count == 0:
        if critical_count == 0:
            print("🎉 All artifacts are valid and follow anti-checklist methodology!")
            print(" Ready for build and deployment")
            return 0
        else:
            print(f"  {critical_count} critical methodology issues found")
            print("🔧 Please address anti-checklist methodology requirements")
            return 1
    else:
        print(f" {invalid_count} artifacts failed validation")
        if critical_count > 0:
            print(f" Including {critical_count} critical methodology issues")
        print(" Please fix errors before building")
        return 1

if __name__ == "__main__":
    exit(main())
