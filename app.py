"""
FastAPI application for network device log analyzer.

Features:
- Diff analysis and HTML report generation
- Smart query engine for log analysis
- Stateless design for OCP/Kubernetes deployment
- In-memory per-session storage (no database required)
"""
from fastapi import FastAPI, HTTPException, Query, Header
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from pathlib import Path
import os
import io
import zipfile

from core import LogParser, get_settings
from core.masker import DataMasker, MASKING_PROFILES
from core.differ import DiffGenerator, DeviceDiff
from core.query_engine import LogQueryEngine, QueryResult
from core.memory_storage import (
    get_session_manager, populate_session, 
    AnalysisSession, DeviceSummary, CommandSummary
)
from core.report_generator import OptimizedReportGenerator
from core.file_service import get_file_service, FileService

# Initialize FastAPI app
app = FastAPI(
    title="Network Device Log Analyzer",
    description="Stateless analysis of network device change logs - OCP ready",
    version="3.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global services (stateless)
parser = LogParser()
session_manager = get_session_manager()  # In-memory session storage
file_service: FileService = get_file_service()  # File service for local/remote file access



# Request/Response Models
class AnalyzeRequest(BaseModel):
    change_directory: str
    masking_profile: str = "standard"
    masking_categories: Optional[List[str]] = None
    include_unchanged: bool = False


class AnalyzeResponse(BaseModel):
    """Response includes session_id for subsequent queries."""
    message: str
    session_id: str  # Use this for all subsequent API calls
    change_number: str
    total_devices: int
    devices_with_changes: int
    report_url: str
    legacy_report_url: str
    query_available: bool
    statistics: Dict[str, Any]


class QueryRequest(BaseModel):
    question: str
    session_id: Optional[str] = None  # Optional: use header or this field
    filters: Optional[Dict[str, Any]] = None


class QueryResponse(BaseModel):
    answer: str
    change_number: Optional[str] = None
    session_id: Optional[str] = None


class ChangeInfo(BaseModel):
    change_number: str
    total_devices: int
    devices_with_changes: int
    session_id: str


class BrowseRequest(BaseModel):
    path: Optional[str] = None


class RemoteFileRequest(BaseModel):
    remote_path: str
    change_name: str


class RemoteConfigRequest(BaseModel):
    base_url: str
    token: str
    provider: str = "generic"


# Helper to get session from request
def get_session_from_request(
    session_id: Optional[str] = None,
    change_number: Optional[str] = None
) -> AnalysisSession:
    """Get session by ID or change number."""
    session = None
    
    if session_id:
        session = session_manager.get_session(session_id)
    elif change_number:
        session = session_manager.get_session_by_change(change_number)
    
    if not session:
        raise HTTPException(
            status_code=400,
            detail="No active session. Please analyze a change first."
        )
    
    return session


# API Endpoints

@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "Network Device Log Analyzer API",
        "version": "3.0.0",
        "architecture": "stateless",
        "storage": "in-memory per-session"
    }


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    settings = get_settings()
    active_sessions = len(session_manager.list_sessions())
    return {
        "status": "healthy",
        "query_engine": "built-in",
        "storage": "in-memory",
        "active_sessions": active_sessions,
        "masking_enabled": settings.masking.enabled,
        "deployment_mode": file_service.get_mode(),
        "remote_configured": file_service.is_remote_configured()
    }


# ==================== File Browsing Endpoints ====================

@app.get("/api/environment")
async def get_environment():
    """Get deployment environment information."""
    return {
        "mode": file_service.get_mode(),
        "is_local": file_service.is_local_mode(),
        "remote_configured": file_service.is_remote_configured(),
        "features": {
            "folder_browse": file_service.is_local_mode(),
            "remote_files": file_service.is_remote_configured()
        }
    }


@app.get("/api/browse/drives")
async def browse_drives():
    """Get available drives (Windows) or mount points (Linux/Mac)."""
    if not file_service.is_local_mode():
        raise HTTPException(
            status_code=400,
            detail="Folder browsing only available in local mode"
        )
    
    try:
        drives = file_service.get_drives()
        return {
            "drives": [
                {"name": d.name, "path": d.path}
                for d in drives
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/browse/directory")
async def browse_directory(request: BrowseRequest):
    """Browse a local directory."""
    if not file_service.is_local_mode():
        raise HTTPException(
            status_code=400,
            detail="Folder browsing only available in local mode"
        )
    
    path = request.path
    if not path:
        # Return drives/root
        drives = file_service.get_drives()
        return {
            "path": "",
            "parent": None,
            "items": [
                {
                    "name": d.name,
                    "path": d.path,
                    "is_directory": True,
                    "size": None
                }
                for d in drives
            ]
        }
    
    try:
        items = file_service.list_directory(path)
        return {
            "path": path,
            "parent": file_service.get_parent_path(path),
            "items": [
                {
                    "name": item.name,
                    "path": item.path,
                    "is_directory": item.is_directory,
                    "size": item.size
                }
                for item in items
            ]
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Directory not found")
    except PermissionError:
        raise HTTPException(status_code=403, detail="Permission denied")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/browse/validate")
async def validate_change_directory(request: BrowseRequest):
    """Validate that a directory is a valid change directory with pre/post folders."""
    if not request.path:
        raise HTTPException(status_code=400, detail="Path is required")
    
    is_valid, message = file_service.validate_change_directory(request.path)
    return {
        "valid": is_valid,
        "message": message,
        "path": request.path
    }


# ==================== Remote File Service Endpoints ====================

@app.post("/api/remote/configure")
async def configure_remote_service(request: RemoteConfigRequest):
    """Configure remote file service connection (for OpenShift mode)."""
    global file_service
    
    # Update configuration
    import os
    os.environ['FILE_SERVICE_URL'] = request.base_url
    os.environ['FILE_SERVICE_TOKEN'] = request.token
    
    # Reinitialize file service with new config
    config = {
        'app': {'mode': 'openshift'},
        'file_service': {
            'provider': request.provider,
            'base_url': request.base_url,
            'token': request.token
        }
    }
    file_service = get_file_service(config)
    
    # Test connection
    success, message = await file_service.test_connection()
    
    return {
        "configured": success,
        "message": message,
        "provider": request.provider
    }


@app.get("/api/remote/test")
async def test_remote_connection():
    """Test connection to remote file service."""
    if not file_service.is_remote_configured():
        return {
            "connected": False,
            "message": "Remote file service not configured"
        }
    
    success, message = await file_service.test_connection()
    return {
        "connected": success,
        "message": message
    }


@app.post("/api/remote/browse")
async def browse_remote_directory(request: BrowseRequest):
    """Browse remote file service directory."""
    if not file_service.is_remote_configured():
        raise HTTPException(
            status_code=400,
            detail="Remote file service not configured"
        )
    
    try:
        path = request.path or "/"
        items = await file_service.list_remote_directory(path)
        
        return {
            "path": path,
            "parent": file_service.get_parent_path(path) if path != "/" else None,
            "items": [
                {
                    "name": item.name,
                    "path": item.path,
                    "is_directory": item.is_directory,
                    "size": item.size,
                    "modified": item.modified
                }
                for item in items
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/remote/download")
async def download_remote_change(request: RemoteFileRequest):
    """Download change directory from remote file service."""
    if not file_service.is_remote_configured():
        raise HTTPException(
            status_code=400,
            detail="Remote file service not configured"
        )
    
    try:
        local_path = await file_service.download_change_directory(
            request.remote_path,
            request.change_name
        )
        
        # Validate the downloaded directory
        is_valid, message = file_service.validate_change_directory(str(local_path))
        
        return {
            "success": True,
            "local_path": str(local_path),
            "valid": is_valid,
            "message": message
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze_change(request: AnalyzeRequest):
    """
    Analyze a change directory and generate diff report.
    Creates a new session for this analysis - use session_id for subsequent queries.
    Stateless design - no persistent database, each session is independent.
    """
    change_path = Path(request.change_directory)
    
    if not change_path.exists():
        raise HTTPException(status_code=404, detail="Change directory not found")
    
    if not change_path.is_dir():
        raise HTTPException(status_code=400, detail="Path is not a directory")
    
    try:
        # Parse logs
        device_logs = parser.parse_change_directory(change_path)
        
        if not device_logs:
            raise HTTPException(status_code=400, detail="No device logs found in directory")
        
        # Set up masking
        masker = DataMasker()
        categories = request.masking_categories
        if request.masking_profile in MASKING_PROFILES:
            categories = MASKING_PROFILES[request.masking_profile]
        
        # Generate diffs
        diff_generator = DiffGenerator(masker=masker, masking_categories=categories)
        device_diffs = []
        
        for hostname, (pre_log, post_log) in device_logs.items():
            if pre_log and post_log:
                device_diff = diff_generator.generate_device_diff(pre_log, post_log)
                device_diffs.append(device_diff)
        
        change_number = change_path.name
        
        # Create a new session and populate it
        session = session_manager.create_session(change_number)
        populate_session(session, device_logs, device_diffs)
        
        # Generate optimized paginated report (for large scale)
        output_dir = Path("reports")
        output_dir.mkdir(exist_ok=True)
        
        # Use optimized report generator for paginated output
        report_gen = OptimizedReportGenerator(masker=masker)
        report_path = report_gen.generate_report(
            change_number,
            device_diffs,
            output_dir
        )
        
        # Also generate legacy single-file report for backward compatibility
        legacy_report_path = output_dir / f"{change_path.name}_report.html"
        diff_generator.generate_html_report(
            device_diffs,
            legacy_report_path,
            include_unchanged=request.include_unchanged
        )
        
        # Get statistics from session
        stats = session.get_statistics()
        
        return AnalyzeResponse(
            message="Analysis complete",
            session_id=session.session_id,
            change_number=change_number,
            total_devices=stats['total_devices'],
            devices_with_changes=stats['changed_devices'],
            report_url=f"/api/report/{change_number}/index.html",
            legacy_report_url=f"/api/report-legacy/{change_number}",
            query_available=True,
            statistics=stats
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/report/{change_number}/{file_path:path}")
async def get_paginated_report(change_number: str, file_path: str):
    """
    Get paginated HTML report files.
    Serves index.html and device pages from reports/<change_number>/
    """
    report_path = Path("reports") / change_number / file_path
    
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found")
    
    return FileResponse(report_path, media_type="text/html")


@app.get("/api/report-legacy/{change_number}")
async def get_legacy_report(change_number: str):
    """Get legacy single-file HTML diff report for a change."""
    report_path = Path("reports") / f"{change_number}_report.html"
    
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    
    return FileResponse(report_path, media_type="text/html")


@app.get("/api/download/{change_number}")
async def download_report(change_number: str, format: str = Query("html", description="Format: html (single file) or zip (all files)")):
    """
    Download the diff report.
    - format=html: Download single-file HTML report
    - format=zip: Download ZIP with all report files (index + device pages)
    """
    if format == "html":
        # Download single-file legacy report
        report_path = Path("reports") / f"{change_number}_report.html"
        if not report_path.exists():
            raise HTTPException(status_code=404, detail="Report not found")
        
        return FileResponse(
            report_path,
            media_type="text/html",
            filename=f"{change_number}_diff_report.html",
            headers={"Content-Disposition": f"attachment; filename={change_number}_diff_report.html"}
        )
    
    elif format == "zip":
        # Create ZIP with all report files
        report_dir = Path("reports") / change_number
        if not report_dir.exists():
            raise HTTPException(status_code=404, detail="Report directory not found")
        
        # Create ZIP in memory
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            for file_path in report_dir.rglob("*.html"):
                arcname = file_path.relative_to(report_dir)
                zip_file.write(file_path, arcname)
            
            # Also include legacy single-file if exists
            legacy_path = Path("reports") / f"{change_number}_report.html"
            if legacy_path.exists():
                zip_file.write(legacy_path, f"{change_number}_complete.html")
        
        zip_buffer.seek(0)
        
        return StreamingResponse(
            zip_buffer,
            media_type="application/zip",
            headers={"Content-Disposition": f"attachment; filename={change_number}_reports.zip"}
        )
    
    else:
        raise HTTPException(status_code=400, detail="Invalid format. Use 'html' or 'zip'")


@app.get("/api/devices")
async def get_devices_paginated(
    session_id: Optional[str] = Query(None, description="Session ID from analyze response"),
    change_number: Optional[str] = Query(None, description="Change number (alternative to session_id)"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=10, le=200, description="Items per page"),
    status: Optional[str] = Query(None, description="Filter by status: changed, unchanged, errors"),
    sort_by: str = Query("hostname", description="Sort field")
):
    """
    Get paginated list of devices for the analyzed change.
    Requires session_id or change_number from the analyze response.
    """
    session = get_session_from_request(session_id, change_number)
    
    devices, total = session.get_devices_paginated(page, page_size, status)
    
    total_pages = (total + page_size - 1) // page_size
    
    return {
        "devices": [
            {
                "hostname": d.hostname,
                "total_commands": d.total_commands,
                "commands_with_changes": d.commands_with_changes,
                "status": d.status,
                "has_interface_changes": d.has_interface_changes,
                "has_bgp_changes": d.has_bgp_changes,
                "has_ospf_changes": d.has_ospf_changes
            }
            for d in devices
        ],
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_items": total,
            "total_pages": total_pages
        },
        "session_id": session.session_id
    }


@app.get("/api/devices/{hostname}/commands")
async def get_device_commands(
    hostname: str,
    session_id: Optional[str] = Query(None, description="Session ID from analyze response"),
    change_number: Optional[str] = Query(None, description="Change number (alternative to session_id)"),
    changed_only: bool = Query(False, description="Only return changed commands")
):
    """Get list of commands for a specific device."""
    session = get_session_from_request(session_id, change_number)
    
    commands = session.get_device_commands(hostname, changed_only)
    
    if not commands:
        raise HTTPException(status_code=404, detail="Device not found")
    
    return {
        "hostname": hostname,
        "commands": [
            {
                "command": c.command,
                "has_changes": c.has_changes,
                "added_lines": c.added_lines,
                "removed_lines": c.removed_lines
            }
            for c in commands
        ],
        "session_id": session.session_id
    }


@app.get("/api/devices/{hostname}/diff/{command:path}")
async def get_command_diff(
    hostname: str,
    command: str,
    session_id: Optional[str] = Query(None, description="Session ID from analyze response"),
    change_number: Optional[str] = Query(None, description="Change number (alternative to session_id)")
):
    """Get diff for a specific command on a device."""
    session = get_session_from_request(session_id, change_number)
    
    diff_data = session.get_command_diff(hostname, command)
    
    if not diff_data:
        raise HTTPException(status_code=404, detail="Command not found")
    
    return diff_data


@app.get("/api/statistics")
async def get_change_statistics(
    session_id: Optional[str] = Query(None, description="Session ID from analyze response"),
    change_number: Optional[str] = Query(None, description="Change number (alternative to session_id)")
):
    """Get detailed statistics for the analyzed change."""
    session = get_session_from_request(session_id, change_number)
    
    return session.get_statistics()


@app.get("/api/search/devices")
async def search_devices(
    q: str = Query(..., min_length=1, description="Search query"),
    session_id: Optional[str] = Query(None, description="Session ID from analyze response"),
    change_number: Optional[str] = Query(None, description="Change number (alternative to session_id)")
):
    """Search devices by hostname."""
    session = get_session_from_request(session_id, change_number)
    
    devices = session.search_devices(q)
    return {"results": devices, "session_id": session.session_id}


@app.get("/api/change/info", response_model=ChangeInfo)
async def get_change_info(
    session_id: Optional[str] = Query(None, description="Session ID from analyze response"),
    change_number: Optional[str] = Query(None, description="Change number (alternative to session_id)")
):
    """Get information about an analyzed change."""
    session = get_session_from_request(session_id, change_number)
    
    stats = session.get_statistics()
    
    return ChangeInfo(
        change_number=session.change_number,
        total_devices=stats['total_devices'],
        devices_with_changes=stats['changed_devices'],
        session_id=session.session_id
    )


@app.post("/api/chat", response_model=QueryResponse)
async def chat_query(request: QueryRequest):
    """
    Query the analyzed logs using natural language.
    Uses built-in query engine.
    Requires session_id or will use most recent session.
    """
    # Get session - either from request or find by change_number
    session = None
    if request.session_id:
        session = session_manager.get_session(request.session_id)
    
    if not session:
        # Try to find most recent session
        sessions = session_manager.list_sessions()
        if sessions:
            session = session_manager.get_session(sessions[-1]['session_id'])
    
    if not session:
        raise HTTPException(
            status_code=400,
            detail="No active session. Please analyze a change first."
        )
    
    try:
        # Create a query engine for this session's data
        query_engine = LogQueryEngine(session.device_logs, session.device_diffs)
        result = query_engine.query(request.question)
        
        return QueryResponse(
            answer=result.summary,
            change_number=session.change_number,
            session_id=session.session_id
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/sessions")
async def list_active_sessions():
    """List all active sessions. Useful for debugging and monitoring."""
    sessions = session_manager.list_sessions()
    return {
        "sessions": sessions,
        "total": len(sessions),
        "max_sessions": 100,
        "ttl_minutes": 30
    }


@app.delete("/api/sessions/{session_id}")
async def delete_session(session_id: str):
    """Manually delete a session to free memory."""
    removed = session_manager.remove_session(session_id)
    if removed:
        return {"message": f"Session {session_id} removed"}
    else:
        raise HTTPException(status_code=404, detail="Session not found")


@app.get("/api/query/suggestions")
async def get_query_suggestions():
    """Get suggested queries based on current analysis."""
    return {
        "suggestions": [
            {"query": "Did any interface status change?", "category": "Interface"},
            {"query": "What interfaces went down?", "category": "Interface"},
            {"query": "What interfaces came up?", "category": "Interface"},
            {"query": "Show me all errors", "category": "Errors"},
            {"query": "What BGP changes occurred?", "category": "BGP"},
            {"query": "What OSPF changes occurred?", "category": "OSPF"},
            {"query": "Show routing changes", "category": "Routing"},
            {"query": "What VLANs changed?", "category": "VLAN"},
            {"query": "Show configuration changes", "category": "Config"},
            {"query": "Give me a change summary", "category": "Summary"},
        ]
    }


@app.get("/api/masking/profiles")
async def get_masking_profiles():
    """Get available masking profiles."""
    return {
        "profiles": list(MASKING_PROFILES.keys()),
        "descriptions": {
            "minimal": "Mask only timestamps",
            "standard": "Mask timestamps, session IDs, and uptime",
            "strict": "Mask all dynamic data including counters",
            "all": "Apply all masking rules"
        }
    }


@app.get("/api/masking/categories")
async def get_masking_categories():
    """Get available masking categories."""
    masker = DataMasker()
    categories = masker.get_available_categories()
    
    return {
        "categories": categories,
        "rules": {cat: masker.get_category_rules(cat) for cat in categories}
    }


# Serve frontend
@app.get("/ui", response_class=HTMLResponse)
async def serve_ui():
    """Serve the web UI."""
    ui_path = Path(__file__).parent / "frontend" / "index.html"
    
    if ui_path.exists():
        return FileResponse(ui_path)
    else:
        return HTMLResponse(content="""
        <html>
            <head><title>Network Device Log Analyzer</title></head>
            <body>
                <h1>Network Device Log Analyzer</h1>
                <p>Frontend not found. API is available at <a href="/docs">/docs</a></p>
            </body>
        </html>
        """)


if __name__ == "__main__":
    import uvicorn
    settings = get_settings()
    
    uvicorn.run(
        "app:app",
        host=settings.app.host,
        port=settings.app.port,
        reload=settings.app.debug
    )
