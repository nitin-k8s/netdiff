"""
Data masking utilities for log analysis.

Masks sensitive or dynamic data like timestamps, session IDs, counters, etc.
"""
import re
from typing import Dict, List, Optional
from dataclasses import dataclass

from core.config import get_settings


@dataclass
class MaskingRule:
    """Represents a single masking rule."""
    pattern: str
    replacement: str
    compiled_regex: re.Pattern
    
    def apply(self, text: str) -> str:
        """Apply this masking rule to text."""
        return self.compiled_regex.sub(self.replacement, text)


class DataMasker:
    """Handles data masking for log outputs."""
    
    def __init__(self, custom_rules: Optional[Dict[str, List[dict]]] = None):
        """
        Initialize the data masker.
        
        Args:
            custom_rules: Optional custom masking rules. If None, loads from config.
        """
        settings = get_settings()
        
        if custom_rules is None:
            custom_rules = settings.masking.rules if settings.masking.enabled else {}
        
        self.enabled = settings.masking.enabled
        self.rules: Dict[str, List[MaskingRule]] = {}
        
        # Compile all regex patterns
        for category, rules in custom_rules.items():
            self.rules[category] = []
            for rule in rules:
                try:
                    compiled = re.compile(rule['pattern'])
                    self.rules[category].append(MaskingRule(
                        pattern=rule['pattern'],
                        replacement=rule['replacement'],
                        compiled_regex=compiled
                    ))
                except re.error as e:
                    print(f"Warning: Invalid regex pattern in {category}: {rule['pattern']} - {e}")
    
    def mask_text(self, text: str, categories: Optional[List[str]] = None) -> str:
        """
        Apply masking rules to text.
        
        Args:
            text: Text to mask
            categories: List of rule categories to apply. If None, applies all.
            
        Returns:
            Masked text
        """
        if not self.enabled or not text:
            return text
        
        masked_text = text
        
        # Determine which categories to apply
        if categories is None:
            categories = list(self.rules.keys())
        
        # Apply rules from each category
        for category in categories:
            if category in self.rules:
                for rule in self.rules[category]:
                    masked_text = rule.apply(masked_text)
        
        return masked_text
    
    def mask_command_output(self, command: str, output: str, 
                           categories: Optional[List[str]] = None) -> tuple[str, str]:
        """
        Mask both command and output.
        
        Args:
            command: Command string
            output: Output string
            categories: List of rule categories to apply
            
        Returns:
            Tuple of (masked_command, masked_output)
        """
        masked_command = self.mask_text(command, categories)
        masked_output = self.mask_text(output, categories)
        return masked_command, masked_output
    
    def get_available_categories(self) -> List[str]:
        """Get list of available masking categories."""
        return list(self.rules.keys())
    
    def add_custom_rule(self, category: str, pattern: str, replacement: str):
        """
        Add a custom masking rule at runtime.
        
        Args:
            category: Category name
            pattern: Regex pattern
            replacement: Replacement string
        """
        try:
            compiled = re.compile(pattern)
            rule = MaskingRule(
                pattern=pattern,
                replacement=replacement,
                compiled_regex=compiled
            )
            
            if category not in self.rules:
                self.rules[category] = []
            
            self.rules[category].append(rule)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {pattern} - {e}")
    
    def remove_category(self, category: str):
        """Remove all rules in a category."""
        if category in self.rules:
            del self.rules[category]
    
    def get_category_rules(self, category: str) -> List[Dict[str, str]]:
        """Get all rules in a category."""
        if category not in self.rules:
            return []
        
        return [
            {"pattern": rule.pattern, "replacement": rule.replacement}
            for rule in self.rules[category]
        ]


# Predefined masking profiles
MASKING_PROFILES = {
    "minimal": ["timestamps"],
    "standard": ["timestamps", "session_ids", "uptime"],
    "strict": ["timestamps", "session_ids", "counters", "uptime"],
    "all": None  # Apply all categories
}


def get_masker_for_profile(profile: str = "standard") -> DataMasker:
    """
    Get a DataMasker configured for a specific profile.
    
    Args:
        profile: One of "minimal", "standard", "strict", or "all"
        
    Returns:
        Configured DataMasker instance
    """
    if profile not in MASKING_PROFILES:
        raise ValueError(f"Unknown profile: {profile}. Use one of {list(MASKING_PROFILES.keys())}")
    
    return DataMasker()
