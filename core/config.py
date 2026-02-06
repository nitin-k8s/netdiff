"""
Configuration management for the log analyzer application.
"""
import os
from pathlib import Path
from typing import Any, Dict, Optional
import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class MaskingConfig(BaseModel):
    enabled: bool = True
    rules: Dict[str, list] = Field(default_factory=dict)


class PerformanceConfig(BaseModel):
    max_workers: int = 10
    chunk_size: int = 1000


class AppConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8002
    debug: bool = True
    mode: str = "auto"  # "local", "openshift", or "auto"


class DiffConfig(BaseModel):
    context_lines: int = 3
    ignore_whitespace: bool = False


class FileServiceConfig(BaseModel):
    """Configuration for remote file sharing service."""
    provider: str = "generic"  # nexus, artifactory, sharepoint, s3, generic
    base_url: str = ""
    token: str = ""
    headers: Dict[str, str] = Field(default_factory=dict)
    download_dir: str = "downloads"
    timeout: int = 30


class Settings(BaseSettings):
    """Application settings loaded from config.yaml and environment variables."""
    
    masking: MaskingConfig = Field(default_factory=MaskingConfig)
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
    app: AppConfig = Field(default_factory=AppConfig)
    diff: DiffConfig = Field(default_factory=DiffConfig)
    file_service: FileServiceConfig = Field(default_factory=FileServiceConfig)
    
    class Config:
        env_file = ".env"
        env_nested_delimiter = "__"
        extra = "ignore"  # Ignore extra fields in config


def load_config(config_path: Optional[Path] = None) -> Settings:
    """Load configuration from YAML file and environment variables."""
    if config_path is None:
        config_path = Path(__file__).parent.parent / "config.yaml"
    
    # Load YAML config
    config_data = {}
    if config_path.exists():
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f) or {}
    
    # Replace environment variable placeholders
    config_data = _replace_env_vars(config_data)
    
    # Create Settings instance
    return Settings(**config_data)


def _replace_env_vars(data: Any) -> Any:
    """Recursively replace ${ENV_VAR} placeholders with environment variables."""
    if isinstance(data, dict):
        return {k: _replace_env_vars(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_replace_env_vars(item) for item in data]
    elif isinstance(data, str) and data.startswith("${") and data.endswith("}"):
        env_var = data[2:-1]
        return os.getenv(env_var, data)
    return data


# Global settings instance
settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get the global settings instance."""
    global settings
    if settings is None:
        settings = load_config()
    return settings
