"""
File Service Module for Network Device Log Analyzer.

Supports both local file browsing and remote file sharing service access.
Used when running locally (folder browser) or on OpenShift (API-based file access).
"""
import os
import shutil
import tempfile
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import httpx
import asyncio
import zipfile
import tarfile


class DeploymentMode(Enum):
    """Application deployment mode."""
    LOCAL = "local"
    OPENSHIFT = "openshift"
    AUTO = "auto"


class FileServiceProvider(Enum):
    """Supported file sharing service providers."""
    GENERIC = "generic"  # Generic HTTP file server
    NEXUS = "nexus"      # Sonatype Nexus Repository
    ARTIFACTORY = "artifactory"  # JFrog Artifactory
    SHAREPOINT = "sharepoint"    # Microsoft SharePoint
    S3 = "s3"            # AWS S3 compatible


@dataclass
class FileInfo:
    """Information about a file or directory."""
    name: str
    path: str
    is_directory: bool
    size: Optional[int] = None
    modified: Optional[str] = None


@dataclass
class RemoteFileConfig:
    """Configuration for remote file service."""
    provider: FileServiceProvider
    base_url: str
    token: str
    headers: Dict[str, str]
    download_dir: Path
    timeout: int = 30


class FileService:
    """
    File service that handles both local and remote file access.
    
    For local mode: Provides folder browsing capabilities
    For OpenShift mode: Connects to file sharing service via API
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize file service with configuration."""
        self.config = config or {}
        self.mode = self._detect_mode()
        self.remote_config = self._init_remote_config() if self.mode == DeploymentMode.OPENSHIFT else None
        
    def _detect_mode(self) -> DeploymentMode:
        """Detect deployment mode from config or environment."""
        config_mode = self.config.get('app', {}).get('mode', 'auto')
        
        if config_mode == 'auto':
            # Check for OpenShift environment variables
            if os.environ.get('OPENSHIFT_BUILD_NAME') or \
               os.environ.get('KUBERNETES_SERVICE_HOST') or \
               os.environ.get('RUNNING_IN_CONTAINER'):
                return DeploymentMode.OPENSHIFT
            return DeploymentMode.LOCAL
        
        return DeploymentMode(config_mode)
    
    def _init_remote_config(self) -> Optional[RemoteFileConfig]:
        """Initialize remote file service configuration."""
        file_config = self.config.get('file_service', {})
        
        # Token from environment takes precedence
        token = os.environ.get('FILE_SERVICE_TOKEN', file_config.get('token', ''))
        base_url = os.environ.get('FILE_SERVICE_URL', file_config.get('base_url', ''))
        
        if not base_url:
            return None
            
        provider = FileServiceProvider(file_config.get('provider', 'generic'))
        download_dir = Path(file_config.get('download_dir', 'downloads'))
        download_dir.mkdir(parents=True, exist_ok=True)
        
        return RemoteFileConfig(
            provider=provider,
            base_url=base_url.rstrip('/'),
            token=token,
            headers=file_config.get('headers', {}),
            download_dir=download_dir,
            timeout=file_config.get('timeout', 30)
        )
    
    def get_mode(self) -> str:
        """Get current deployment mode."""
        return self.mode.value
    
    def is_local_mode(self) -> bool:
        """Check if running in local mode."""
        return self.mode == DeploymentMode.LOCAL
    
    def is_remote_configured(self) -> bool:
        """Check if remote file service is configured."""
        return self.remote_config is not None and bool(self.remote_config.base_url)
    
    # ==================== Local File Operations ====================
    
    def list_directory(self, path: str) -> List[FileInfo]:
        """
        List contents of a local directory.
        For local mode folder browsing.
        """
        dir_path = Path(path)
        
        if not dir_path.exists():
            raise FileNotFoundError(f"Directory not found: {path}")
        
        if not dir_path.is_dir():
            raise NotADirectoryError(f"Not a directory: {path}")
        
        items = []
        try:
            for item in sorted(dir_path.iterdir()):
                try:
                    stat = item.stat()
                    items.append(FileInfo(
                        name=item.name,
                        path=str(item.absolute()),
                        is_directory=item.is_dir(),
                        size=stat.st_size if item.is_file() else None,
                        modified=str(stat.st_mtime)
                    ))
                except PermissionError:
                    # Skip items we can't access
                    items.append(FileInfo(
                        name=item.name,
                        path=str(item.absolute()),
                        is_directory=item.is_dir(),
                        size=None,
                        modified=None
                    ))
        except PermissionError:
            raise PermissionError(f"Permission denied: {path}")
        
        return items
    
    def get_drives(self) -> List[FileInfo]:
        """
        Get list of available drives (Windows) or mount points (Linux/Mac).
        For local mode root browsing.
        """
        import platform
        
        if platform.system() == 'Windows':
            # Windows: List available drive letters
            import string
            drives = []
            for letter in string.ascii_uppercase:
                drive = f"{letter}:\\"
                if Path(drive).exists():
                    drives.append(FileInfo(
                        name=f"{letter}:",
                        path=drive,
                        is_directory=True
                    ))
            return drives
        else:
            # Unix-like: Return common mount points
            mount_points = ['/', '/home', '/mnt', '/tmp']
            return [
                FileInfo(name=mp, path=mp, is_directory=True)
                for mp in mount_points if Path(mp).exists()
            ]
    
    def validate_change_directory(self, path: str) -> Tuple[bool, str]:
        """
        Validate that a directory contains device folders with pre/post log files.
        
        Expected structure:
        <path>/
          <hostname>/
            *pre*.log or *pre*.txt
            *post*.log or *post*.txt
        """
        dir_path = Path(path)
        
        if not dir_path.exists():
            return False, "Directory does not exist"
        
        if not dir_path.is_dir():
            return False, "Path is not a directory"
        
        # Look for device directories containing pre/post files
        device_count = 0
        for item in dir_path.iterdir():
            if item.is_dir():
                # Check if this looks like a device directory (has pre or post files)
                pre_files = list(item.glob("*pre*.log")) + list(item.glob("*pre*.txt"))
                post_files = list(item.glob("*post*.log")) + list(item.glob("*post*.txt"))
                
                if pre_files or post_files:
                    device_count += 1
        
        if device_count == 0:
            return False, "No device directories found with pre/post log files"
        
        return True, f"Valid directory with {device_count} device(s)"
    
    # ==================== Remote File Operations ====================
    
    async def list_remote_directory(self, path: str = "/") -> List[FileInfo]:
        """
        List contents of a remote directory from file sharing service.
        """
        if not self.remote_config:
            raise RuntimeError("Remote file service not configured")
        
        headers = self._get_auth_headers()
        url = f"{self.remote_config.base_url}/list"
        
        async with httpx.AsyncClient(timeout=self.remote_config.timeout) as client:
            response = await client.get(url, params={"path": path}, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            items = []
            
            for item in data.get('items', data.get('files', [])):
                items.append(FileInfo(
                    name=item.get('name', item.get('filename', '')),
                    path=item.get('path', item.get('fullPath', '')),
                    is_directory=item.get('isDirectory', item.get('type') == 'directory'),
                    size=item.get('size'),
                    modified=item.get('modified', item.get('lastModified'))
                ))
            
            return items
    
    async def download_change_directory(self, remote_path: str, change_name: str) -> Path:
        """
        Download a change directory (or archive) from remote file service.
        Returns the local path to the downloaded/extracted directory.
        """
        if not self.remote_config:
            raise RuntimeError("Remote file service not configured")
        
        local_dir = self.remote_config.download_dir / change_name
        local_dir.mkdir(parents=True, exist_ok=True)
        
        headers = self._get_auth_headers()
        
        # Check if it's an archive file
        if remote_path.endswith(('.zip', '.tar.gz', '.tgz', '.tar')):
            return await self._download_and_extract_archive(remote_path, local_dir, headers)
        else:
            # Download directory structure
            return await self._download_directory(remote_path, local_dir, headers)
    
    async def _download_and_extract_archive(
        self, remote_path: str, local_dir: Path, headers: Dict[str, str]
    ) -> Path:
        """Download and extract an archive file."""
        archive_name = Path(remote_path).name
        archive_path = local_dir / archive_name
        
        # Download the archive
        url = f"{self.remote_config.base_url}/download"
        
        async with httpx.AsyncClient(timeout=self.remote_config.timeout * 3) as client:
            async with client.stream('GET', url, params={"path": remote_path}, headers=headers) as response:
                response.raise_for_status()
                
                with open(archive_path, 'wb') as f:
                    async for chunk in response.aiter_bytes(chunk_size=8192):
                        f.write(chunk)
        
        # Extract the archive
        extract_dir = local_dir / "extracted"
        extract_dir.mkdir(exist_ok=True)
        
        if archive_name.endswith('.zip'):
            with zipfile.ZipFile(archive_path, 'r') as zf:
                zf.extractall(extract_dir)
        elif archive_name.endswith(('.tar.gz', '.tgz', '.tar')):
            with tarfile.open(archive_path, 'r:*') as tf:
                tf.extractall(extract_dir)
        
        # Clean up archive
        archive_path.unlink()
        
        # Find the change directory (with pre/post subdirs)
        for item in extract_dir.iterdir():
            if item.is_dir():
                pre = item / "pre"
                post = item / "post"
                if pre.exists() and post.exists():
                    return item
        
        # If no pre/post found, assume extracted dir is the change dir
        return extract_dir
    
    async def _download_directory(
        self, remote_path: str, local_dir: Path, headers: Dict[str, str]
    ) -> Path:
        """Download a directory structure recursively."""
        url = f"{self.remote_config.base_url}/download-dir"
        
        async with httpx.AsyncClient(timeout=self.remote_config.timeout * 5) as client:
            response = await client.post(
                url,
                json={"path": remote_path},
                headers=headers
            )
            response.raise_for_status()
            
            # Assuming server returns a zip of the directory
            zip_path = local_dir / "download.zip"
            with open(zip_path, 'wb') as f:
                f.write(response.content)
            
            # Extract
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(local_dir)
            
            zip_path.unlink()
            
            return local_dir
    
    async def download_file(self, remote_path: str, local_path: Path) -> Path:
        """Download a single file from remote service."""
        if not self.remote_config:
            raise RuntimeError("Remote file service not configured")
        
        headers = self._get_auth_headers()
        url = f"{self.remote_config.base_url}/download"
        
        local_path.parent.mkdir(parents=True, exist_ok=True)
        
        async with httpx.AsyncClient(timeout=self.remote_config.timeout * 2) as client:
            async with client.stream('GET', url, params={"path": remote_path}, headers=headers) as response:
                response.raise_for_status()
                
                with open(local_path, 'wb') as f:
                    async for chunk in response.aiter_bytes(chunk_size=8192):
                        f.write(chunk)
        
        return local_path
    
    async def test_connection(self) -> Tuple[bool, str]:
        """Test connection to remote file service."""
        if not self.remote_config:
            return False, "Remote file service not configured"
        
        if not self.remote_config.base_url:
            return False, "No base URL configured"
        
        headers = self._get_auth_headers()
        
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                # Try a simple health/list endpoint
                for endpoint in ['/health', '/api/health', '/list', '/']:
                    try:
                        url = f"{self.remote_config.base_url}{endpoint}"
                        response = await client.get(url, headers=headers)
                        if response.status_code < 500:
                            return True, f"Connected to {self.remote_config.provider.value} service"
                    except:
                        continue
                
                return False, "Could not reach file service"
        except httpx.TimeoutException:
            return False, "Connection timed out"
        except Exception as e:
            return False, f"Connection failed: {str(e)}"
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for remote service."""
        headers = dict(self.remote_config.headers) if self.remote_config else {}
        
        if self.remote_config and self.remote_config.token:
            # Add token based on provider type
            if self.remote_config.provider == FileServiceProvider.NEXUS:
                headers['Authorization'] = f'Basic {self.remote_config.token}'
            elif self.remote_config.provider == FileServiceProvider.ARTIFACTORY:
                headers['X-JFrog-Art-Api'] = self.remote_config.token
            elif self.remote_config.provider == FileServiceProvider.SHAREPOINT:
                headers['Authorization'] = f'Bearer {self.remote_config.token}'
            elif self.remote_config.provider == FileServiceProvider.S3:
                # S3 uses different auth mechanism (handled separately)
                headers['Authorization'] = f'AWS {self.remote_config.token}'
            else:
                # Generic: Try Bearer token
                headers['Authorization'] = f'Bearer {self.remote_config.token}'
        
        return headers
    
    # ==================== Utility Methods ====================
    
    def get_parent_path(self, path: str) -> str:
        """Get parent directory path."""
        return str(Path(path).parent)
    
    def cleanup_downloads(self, older_than_days: int = 7):
        """Clean up old downloaded files."""
        if not self.remote_config:
            return
        
        import time
        cutoff = time.time() - (older_than_days * 24 * 60 * 60)
        
        for item in self.remote_config.download_dir.iterdir():
            if item.stat().st_mtime < cutoff:
                if item.is_dir():
                    shutil.rmtree(item)
                else:
                    item.unlink()


# Singleton instance
_file_service: Optional[FileService] = None


def get_file_service(config: Optional[Dict[str, Any]] = None) -> FileService:
    """Get or create the file service singleton."""
    global _file_service
    
    if _file_service is None or config is not None:
        _file_service = FileService(config)
    
    return _file_service
