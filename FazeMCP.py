import base64
import binascii
import os
import re

import requests
from mcp.server.fastmcp import FastMCP

FazeMCP_Version = "1.0.1"
FazeMCP_URL = "https://docs.faze.security/"
FazeDescriptio = """
Faze Description:
    Faze is an Agentic Red Team: The Future of Web and API Security
    Empower your cybersecurity with Faze’s Agentic-AI Red Team. Our autonomous platform perform continuous penetration testing, adapt in
    real-time, and uncover vulnerabilities others miss. By combining human insight with AI, 
    Faze enhances your web security posture without relying on external consultants keeping you proactive, efficient, and ahead of threats.

    FazeMCP is a powerful automation engine within the Faze platform, designed to seamlessly execute security operations, 
    Execute Penetration Testing, and integration workflows through simple API-driven AI tasks. It empowers cybersecurity teams to automate their penetration testing, 
    streamline remediation processes, and integrate with third-party tools like Jira, Slack, and AWS.

    Faze is an advanced AI-driven cybersecurity platform that specializes in automated penetration testing, 
    real-time threat detection, and exploit generation. Built for enterprises and governments, Faze combines 
    machine learning with deep security knowledge to identify vulnerabilities across web applications, APIs, 
    and infrastructure—prioritizing critical risks and providing actionable insights. Its modular design supports 
    dynamic attack surface mapping, continuous monitoring, and rapid integration, making it ideal for both offensive 
    and defensive security teams.
"""

mcp = FastMCP("FazeMCP-ART")
API_KEY = os.getenv("API_KEY", "")
API_GATEWAY = os.getenv("API_GATEWAY", "https://api.faze.security/")
API_TIMEOUT = int(os.getenv("API_TIMEOUT", "30"))


# --------------------------------------------------------------------------- #
# Shared request helpers
#
# Every tool goes through `_post_json` (JSON endpoints) or `_post_binary`
# (file/export endpoints). Those helpers own ALL transport concerns:
#   - the gateway URL (`_api_url`)
#   - authentication: the API key is sent ONLY as the `Apikey` header
#     (`_api_headers`) — never in the body
#   - the request timeout (`API_TIMEOUT`) and error handling (`_api_error`)
#
# Tools must NOT build their own `headers` dict and must NOT put `apiKey`,
# `db_token`, `pwd`, `user_id` or `function` in the body — the gateway injects
# those from the API key. Keep tool bodies to business fields only.
# --------------------------------------------------------------------------- #
def _api_url(path: str) -> str:
    return f"{API_GATEWAY.rstrip('/')}/{path}"


def _api_headers() -> dict:
    return {"Apikey": API_KEY, "Content-Type": "application/json"}


def _api_error(path: str, message: str, **extra) -> dict:
    payload = {"Error": 1, "Function": path, "Data": message}
    if extra:
        payload["_debug"] = extra
    return payload


def _compact(data: dict) -> dict:
    """Drop keys whose value is ``None`` so optional arguments are omitted from
    the request body and the Public API wrapper applies its own default.
    Meaningful falsy values (``0``, ``False``, ``""``, ``[]``) are preserved.
    """
    return {key: value for key, value in data.items() if value is not None}


def _post_json(path: str, data: dict) -> dict:
    try:
        response = requests.post(
            _api_url(path), headers=_api_headers(), json=data, timeout=API_TIMEOUT,
        )
    except requests.RequestException as exc:
        return _api_error(path, f"Request failed: {exc}")
    if response.status_code != 200:
        return _api_error(
            path, f"HTTP {response.status_code}",
            status_code=response.status_code, body_preview=(response.text or "")[:200],
        )
    try:
        return response.json()
    except ValueError:
        content_type = response.headers.get("Content-Type", "")
        return _api_error(
            path, "Non-JSON response",
            content_type=content_type, body_preview=(response.text or "")[:200],
        )


def _post_file(path: str, fields: dict, file_name: str, file_bytes: bytes) -> dict:
    """POST to a file-upload endpoint as ``multipart/form-data``.

    The backend (`storge.api.api_upload_file`) reads the upload from
    ``request.files['file']``, and the gateway reshaper (`blueprint.redirect_to_api`)
    only rebuilds the *text* fields into ``request.form`` — it never moves a
    JSON/Base64 ``file`` into ``request.files``. So the file MUST travel as a
    real multipart part; the remaining values go as form fields and the API key
    stays in the ``Apikey`` header. We intentionally do NOT set
    ``Content-Type: application/json`` here so ``requests`` emits the multipart
    boundary itself.
    """
    headers = {"Apikey": API_KEY}
    try:
        response = requests.post(
            _api_url(path), headers=headers, data=_compact(fields),
            files={"file": (file_name, file_bytes, "application/octet-stream")},
            timeout=API_TIMEOUT,
        )
    except requests.RequestException as exc:
        return _api_error(path, f"Request failed: {exc}")
    if response.status_code != 200:
        return _api_error(
            path, f"HTTP {response.status_code}",
            status_code=response.status_code, body_preview=(response.text or "")[:200],
        )
    try:
        return response.json()
    except ValueError:
        content_type = response.headers.get("Content-Type", "")
        return _api_error(
            path, "Non-JSON response",
            content_type=content_type, body_preview=(response.text or "")[:200],
        )


_XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def _filename_from_response(response, default: str) -> str:
    """Pull a filename out of the ``Content-Disposition`` header if present,
    otherwise fall back to ``default``. Supports both ``filename="x"`` and
    RFC 5987 ``filename*=UTF-8''x`` forms.
    """
    disposition = response.headers.get("Content-Disposition") or ""
    match = re.search(r"filename\*?=(?:UTF-8'')?\"?([^\";]+)\"?", disposition, re.IGNORECASE)
    if match:
        name = match.group(1).strip()
        if name:
            return name
    return default


def _post_binary(path: str, data: dict, filename: str) -> dict:
    """POST to a file/export endpoint and return a JSON-serializable envelope.

    The Public API returns the raw file bytes for export endpoints. Raw ``bytes``
    cannot be serialized back to the MCP client, so we wrap the payload as
    Base64 together with ``filename`` / ``mime_type`` / ``encoding`` metadata.
    Error / non-file responses are surfaced as the standard ``_api_error`` (or
    the backend's own JSON envelope) instead of being silently dropped.
    """
    try:
        response = requests.post(
            _api_url(path), headers=_api_headers(), json=data, timeout=API_TIMEOUT,
        )
    except requests.RequestException as exc:
        return _api_error(path, f"Request failed: {exc}")
    if response.status_code != 200:
        return _api_error(
            path, f"HTTP {response.status_code}",
            status_code=response.status_code, body_preview=(response.text or "")[:200],
        )
    content = response.content or b""
    ct = (response.headers.get("Content-Type") or "").lower()
    # Some error paths return a JSON envelope (not the file). Surface it as-is.
    if content[:1] in (b"{", b"[") or "json" in ct:
        try:
            return response.json()
        except ValueError:
            return _api_error(
                path, "Unexpected non-file response",
                content_type=ct, body_preview=(response.text or "")[:200],
            )
    if not content:
        return _api_error(path, "Empty file response", content_type=ct)
    return {
        "Error": 0,
        "Function": path,
        "filename": _filename_from_response(response, filename),
        "mime_type": response.headers.get("Content-Type") or _XLSX_MIME,
        "encoding": "base64",
        "size": len(content),
        "content_base64": base64.b64encode(content).decode("ascii"),
    }


@mcp.tool()
def get_art_projects(search: str | None = None, limit: int = 20, offset: int = 0) -> dict:
    """
    This endpoint lists the Agentic Red Team (ART) projects the user can access. Each project includes its name, owner, last activity, number of running scans and total vulnerabilities.

    Args:
        search (str, optional): Case-insensitive filter on the project name; defaults to "".
        limit (int, optional): Page size; defaults to 20.
        offset (int, optional): Number of rows to skip for pagination; defaults to 0.

	Returns:
		dict
    """
    path = "GetArtProjects"
    data = {
        "search": search,
        "limit": limit,
        "offset": offset,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def create_art_project(name: str, concurrent_scans: int = 0) -> dict:
    """
    This endpoint creates a new Agentic Red Team (ART) project with the given name and concurrent-scan budget. Admin only.

    Args:
        name (str): The name for the new Agentic Red Team project.
        concurrent_scans (int, optional): How many scans the project is allowed to run concurrently; defaults to 0.

	Returns:
		dict
    """
    path = "CreateArtProject"
    data = {
        "name": name,
        "concurrent_scans": concurrent_scans,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def edit_art_project(art_id: int, name: str) -> dict:
    """
    This endpoint renames an existing Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project to edit.
        name (str): The new name for the project.

	Returns:
		dict
    """
    path = "EditArtProject"
    data = {
        "art_id": art_id,
        "name": name,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def lock_art_project(art_id: int, lock: bool) -> dict:
    """
    This endpoint locks or unlocks an Agentic Red Team (ART) project. A locked project cannot be edited, paused or deleted.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        lock (bool): Set to True to lock the project, False to unlock it.

	Returns:
		dict
    """
    path = "LockArtProject"
    data = {
        "art_id": art_id,
        "lock": lock,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def art_pause(art_id: int) -> dict:
    """
    This endpoint pauses the Agentic Red Team (ART) project and stops all of its running tasks. The project must be in progress.

    Args:
        art_id (int): The id of the Agentic Red Team project to pause.

	Returns:
		dict
    """
    path = "ArtPause"
    data = {
        "art_id": art_id,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def art_unpause(art_id: int) -> dict:
    """
    This endpoint resumes a paused Agentic Red Team (ART) project. The project must be in the paused state.

    Args:
        art_id (int): The id of the Agentic Red Team project to resume.

	Returns:
		dict
    """
    path = "ArtUnpause"
    data = {
        "art_id": art_id,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def get_art_concurrency(art_id: int) -> dict:
    """
    This endpoint returns the configured concurrent-scan budget of an Agentic Red Team (ART) project. Admin only.

    Args:
        art_id (int): The id of the Agentic Red Team project.

	Returns:
		dict
    """
    path = "GetArtConcurrency"
    data = {
        "art_id": art_id,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def get_available_concurrent_scans_for_art(art_id: int) -> dict:
    """
    This endpoint returns how many additional concurrent scans the Agentic Red Team (ART) project can still start right now.

    Args:
        art_id (int): The id of the Agentic Red Team project.

	Returns:
		dict
    """
    path = "GetAvailableConcurrentScansForArt"
    data = {
        "art_id": art_id,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def edit_concurrent_scans(art_id: int, concurrent_scans: int) -> dict:
    """
    This endpoint updates the concurrent-scan budget of an Agentic Red Team (ART) project. Admin only.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        concurrent_scans (int): The new number of scans the project is allowed to run concurrently.

	Returns:
		dict
    """
    path = "EditConcurrentScans"
    data = {
        "art_id": art_id,
        "concurrent_scans": concurrent_scans,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def get_art_vulnerabilities(art_id: int, limit: int | None = None, offset: int = 0, search: str | None = None,
                            order_by: str | None = None, sort: str | None = None, sort_by: bool | None = None,
                            high_btn: bool | None = None, medium_btn: bool | None = None, low_btn: bool | None = None,
                            informative_btn: bool | None = None, from_date: str | None = None,
                            to_date: str | None = None, newest: bool | None = None,
                            fixed: bool | None = None, cve: bool | None = None,
                            third_party: bool | None = None, false_positive: bool | None = None) -> dict:
    """
    This endpoint retrieves the vulnerabilities found for an Agentic Red Team (ART) project, with pagination, search, sorting and severity filtering. Response shape: when NO view filter is set the response is grouped by vulnerability name (per-group COUNT, items and pagination); when ANY view filter (newest / fixed / cve / third_party / false_positive) is set it switches to a FLAT per-finding list (id, url, vuln_name, severity, fixed, falsepositive, token, date, entity_type).

    Args:
        art_id (int): The id of the Agentic Red Team project.
        limit (int, optional): Page size; defaults to a large value when omitted.
        offset (int, optional): Number of rows to skip for pagination; defaults to 0.
        search (str, optional): Free-text filter on the vulnerabilities; defaults to "".
        order_by (str, optional): Field to order by; one of "severity", "name" (the vulnerability name) or "date"; defaults to "severity".
        sort (str, optional): Field to sort by; one of "asset" (the asset/URL) or "name" (the vulnerability name); defaults to "name".
        sort_by (bool, optional): Sort descending when True, ascending when False; defaults to True.
        high_btn (bool, optional): Include high severity vulnerabilities; set to "True" to filter.
        medium_btn (bool, optional): Include medium severity vulnerabilities; set to "True" to filter.
        low_btn (bool, optional): Include low severity vulnerabilities; set to "True" to filter.
        informative_btn (bool, optional): Include informative vulnerabilities; set to "True" to filter.
        from_date (str, optional): Start date filter (YYYY-MM-DD); defaults to None.
        to_date (str, optional): End date filter (YYYY-MM-DD); defaults to None.
        newest (bool, optional): Sorting modifier only. Set to True to order the findings newest-first by detection date. It never changes which findings are returned, and combines with any of the filters below. Omitted or False, the "order_by"/"sort_by" ordering is used.
        fixed (bool, optional): Set to True to return ONLY findings already marked as fixed. Omitted or False, fixed findings are hidden (the default).
        cve (bool, optional): Set to True to return ONLY findings with a CVE id.
        third_party (bool, optional): Set to True to return ONLY third-party findings (eTLD+1 of the finding differs from the asset it was found on).
        false_positive (bool, optional): Set to True to return ONLY false positives.

    The four filters (fixed / cve / third_party / false_positive) combine with strict AND — each additional one narrows the result (e.g. fixed + cve = only fixed CVE findings).

	Returns:
		dict
    """
    path = "GetArtVulnerabilities"
    data = {
        "art_id": art_id,
        "limit": limit,
        "offset": offset,
        "search": search,
        "order_by": order_by,
        "sort": sort,
        "sort_by": sort_by,
        "high_btn": high_btn,
        "medium_btn": medium_btn,
        "low_btn": low_btn,
        "informative_btn": informative_btn,
        "from_date": from_date,
        "to_date": to_date,
        "newest": newest,
        "fixed": fixed,
        "cve": cve,
        "third_party": third_party,
        "false_positive": false_positive,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def get_newest_vulnerabilities(art_id: int | None = None, limit: int | None = None, offset: int | None = None,
                               desc: bool | None = None) -> dict:
    """
    This endpoint returns a flat list of vulnerabilities ordered by discovery date, either for one Agentic Red Team (ART) project or across every project the API key's user can access. False positives are excluded; fixed and open vulnerabilities are both returned.

    Args:
        art_id (int, optional): The id of the Agentic Red Team project. Omit to list vulnerabilities from all accessible projects.
        limit (int, optional): Page size; defaults to 999. Values of 0 or less also fall back to 999.
        offset (int, optional): Number of rows to skip for pagination; defaults to 0. Negative values fall back to 0.
        desc (bool, optional): True (default) for newest first, False for oldest first.

	Returns:
		dict: {"pagination": {...}, "data": [{id, url, vuln_name, severity, fixed, token, date, entity_type}, ...]}
    """
    path = "GetNewestVulnerabilities"
    data = {
        "art_id": art_id,
        "limit": limit,
        "offset": offset,
        "desc": desc,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def get_art_dashboard(art_id: int) -> dict:
    """
    This endpoint returns the dashboard of an Agentic Red Team (ART) project: header statistics, charts and historical trends.

    Args:
        art_id (int): The id of the Agentic Red Team project.

	Returns:
		dict
    """
    path = "GetArtDashboard"
    data = {
        "art_id": art_id,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def get_top_applications_at_risk(art_id: int, count: int = 5) -> dict:
    """
    This endpoint returns the top applications (assets) at risk for an Agentic Red Team (ART) project,
    ordered by combined high and medium severity vulnerability counts.
    Each entry includes the asset and counts by severity (num_info, num_low, num_med, num_high, num_vulns).

    Args:
        art_id (int): The id of the Agentic Red Team project.
        count (int): Optional number of top applications to return (default 5).

	Returns:
		dict
    """
    path = "GetTopApplicationsAtRisk"
    data = {
        "art_id": art_id,
        "count": count,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def get_most_common_security_issues(art_id: int, count: int = 5) -> dict:
    """
    This endpoint returns the top recurring vulnerability types for an Agentic Red Team (ART) project
    (medium and high severity only). Each entry includes the vulnerability name, its occurrence count,
    severity label, and the number of affected assets.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        count (int): Optional number of top issue types to return (default 5).

	Returns:
		dict
    """
    path = "GetMostCommonSecurityIssues"
    data = {
        "art_id": art_id,
        "count": count,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def get_identities_by_risk_level(
    art_id: int,
    from_date: str,
    to_date: str,
    prev_from_date: str = "",
    prev_to_date: str = "",
    severity: str = "",
) -> dict:
    """
    This endpoint returns vulnerability counts per severity tier (High, Medium, Low, Informative) for an Agentic Red Team (ART) project in a given date range, alongside the equivalent counts for a previous period and the percent change between the two.

    Date intervals are half-open ([from, to)); ``time_create`` is the date field. When ``prev_from_date`` and ``prev_to_date`` are both omitted, the previous period defaults to the same duration immediately before the current period. If only one of them is provided, the other is derived so the previous period matches the current duration.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        from_date (str): Current period start. Accepts ``YYYY-MM-DD`` or ``YYYY-MM-DD HH:MM:SS``.
        to_date (str): Current period end (exclusive).
        prev_from_date (str): Optional previous period start. Defaults are derived (see description).
        prev_to_date (str): Optional previous period end. Defaults are derived (see description).
        severity (str): Optional severity filter. One of ``Informative``, ``Low``, ``Medium``, ``High`` (case-insensitive). Omit for all four tiers.

	Returns:
		dict
    """
    path = "GetIdentitiesByRiskLevel"
    data = {
        "art_id": art_id,
        "from_date": from_date,
        "to_date": to_date,
        "prev_from_date": prev_from_date,
        "prev_to_date": prev_to_date,
        "severity": severity,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def delete_art_project(art_id: int) -> dict:
    """
    This endpoint deletes an Agentic Red Team (ART) project and its related configuration. Admin only and the project must be unlocked.

    Args:
        art_id (int): The id of the Agentic Red Team project to delete.

	Returns:
		dict
    """
    path = "DeleteArtProject"
    data = {
        "art_id": art_id,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def get_agent_instructions(art_id: int) -> dict:
    """
    This endpoint returns the custom agent instructions configured for an Agentic Red Team (ART) project. Requires the Editor role on the project (admins always allowed).

    Args:
        art_id (int): The id of the Agentic Red Team project.

	Returns:
		dict
    """
    path = "GetAgentInstructions"
    data = {
        "art_id": art_id,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def export_dashboard_art(art_id: int, field: str) -> dict:
    """
    This endpoint exports an Agentic Red Team (ART) dashboard widget as an Excel (.xlsx) file.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        field (str): The dashboard field to export. One of: total_assets, vulnerabilities, high_risk, security_score, active_assets, blocked_assets, logins_detected_no_credentials, logins_detected, most_vulnerable_assets, top_vulnerabilities.

    Returns:
        dict
        - On success: {"Error": 0, "Function", "filename", "mime_type",
          "encoding": "base64", "size", "content_base64"}. Decode
          `content_base64` (Base64) to recover the .xlsx file bytes.
        - On failure: {"Error": 1, "Function", "Data"}.
    """
    path = "ExportDashboardArt"
    data = {
        "art_id": art_id,
        "field": field,
    }
    return _post_binary(path, _compact(data), filename=f"dashboard_{field}_{art_id}.xlsx")


# --------------------------------------------------------------------------- #
# Assets
# --------------------------------------------------------------------------- #
@mcp.tool()
def get_assets(art_id: int, search: str | None = None, limit: int = 20, offset: int = 0,
               filter_via_tags: str | None = None, deploy_stage: str | None = None,
               in_progress: str | None = None, asset_state: str | None = None) -> dict:
    """
    This endpoint lists the assets of an Agentic Red Team (ART) project, with search, tag filtering, pagination and status filters.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        search (str, optional): Case-insensitive filter on the asset URL/host; defaults to "".
        limit (int, optional): Page size; defaults to 20.
        offset (int, optional): Number of rows to skip for pagination; defaults to 0.
        filter_via_tags (str, optional): Comma-separated list of tag ids to filter by, e.g. "1,2"; defaults to no filter.
        deploy_stage (str, optional): Filter by deployment stage; defaults to "".
        in_progress (str, optional): Set to "True" to only return assets that are currently scanning; defaults to "".
        asset_state (str, optional): Filter by asset state (e.g. blocked / need_creds / need_schema); defaults to "".

    Returns:
        dict
    """
    path = "GetAssets"
    data = {
        "art_id": art_id,
        "search": search,
        "limit": limit,
        "offset": offset,
        "filter_via_tags": filter_via_tags,
        "deploy_stage": deploy_stage,
        "in_progress": in_progress,
        "asset_state": asset_state,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def get_all_assets(art_id: int) -> dict:
    """
    This endpoint returns a lightweight list of all assets in an Agentic Red Team (ART) project, suitable for dropdowns and bulk selection.

    Args:
        art_id (int): The id of the Agentic Red Team project.

    Returns:
        dict
    """
    path = "GetAllAssets"
    data = {
        "art_id": art_id,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def get_tags(art_id: int) -> dict:
    """
    This endpoint lists the asset tags defined in an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.

    Returns:
        dict
    """
    path = "GetTags"
    data = {
        "art_id": art_id,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def assets_running_summary(art_id: int) -> dict:
    """
    This endpoint returns a summary of the currently running / queued assets of an Agentic Red Team (ART) project, used for status headers and polling.

    Args:
        art_id (int): The id of the Agentic Red Team project.

    Returns:
        dict
    """
    path = "AssetsRunningSummary"
    data = {
        "art_id": art_id,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def add_assets(art_id: int, assets: str | None = None, tags: str | None = None, enable_asm: bool | None = None, assets_excel: str | None = None) -> dict:
    """
    This endpoint adds one or more assets to an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        assets (str): Newline- or comma-separated list of asset URLs/hosts to add, e.g. "https://example.com".
        tags (str, optional): JSON array of tag ids to assign to the new assets, e.g. "[1,2]"; defaults to "".
        enable_asm (bool, optional): Set to True to also run Attack-Surface-Mapping (subdomain discovery) on the added assets; defaults to False.
        assets_excel (str, optional): Source Excel/CSV file name (e.g. "assets.xlsx") to import assets from instead of the `assets` parameter; defaults to "".

    Returns:
        dict
    """
    path = "AddAssets"
    data = {
        "art_id": art_id,
        "assets": assets,
        "tags": tags,
        "enable_asm": enable_asm,
        "assets_excel": assets_excel,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def skip_action(art_id: int, asset_id: int) -> dict:
    """
    This endpoint skips the current running/queued action of a single asset in an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        asset_id (int): The id of the asset whose current action should be skipped; retrieve valid ids via the `GetAssets` endpoint.

    Returns:
        dict
    """
    path = "SkipAction"
    data = {
        "art_id": art_id,
        "asset_id": asset_id,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def remove_assets(art_id: int, asset_ids: str) -> dict:
    """
    This endpoint removes (soft-deletes) one or more assets from an Agentic Red Team (ART) project. Use `restore_assets` to bring them back.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        asset_ids (str): Comma-separated list of asset ids to remove, e.g. "1,2,3"; retrieve valid ids via the `GetAssets` endpoint.

    Returns:
        dict
    """
    path = "RemoveAssets"
    data = {
        "art_id": art_id,
        "asset_ids": asset_ids,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def restore_assets(art_id: int, asset_ids: str) -> dict:
    """
    This endpoint restores one or more previously removed assets in an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        asset_ids (str): Comma-separated list of asset ids to restore, e.g. "1,2,3"; retrieve valid ids via the `GetRemovedAssets` endpoint.

    Returns:
        dict
    """
    path = "RestoreAssets"
    data = {
        "art_id": art_id,
        "asset_ids": asset_ids,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def get_removed_assets(art_id: int) -> dict:
    """
    This endpoint lists the removed (soft-deleted) assets of an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.

    Returns:
        dict
    """
    path = "GetRemovedAssets"
    data = {
        "art_id": art_id,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def lock_asset(art_id: int, asset_id: int, lock: bool) -> dict:
    """
    This endpoint locks or unlocks a single asset in an Agentic Red Team (ART) project. A locked asset will not be scanned.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        asset_id (int): The id of the asset; retrieve valid ids via the `GetAssets` endpoint.
        lock (bool): Set to True to lock the asset, False to unlock it.

    Returns:
        dict
    """
    path = "LockAsset"
    data = {
        "art_id": art_id,
        "asset_id": asset_id,
        "lock": lock,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def add_tags_to_asset(art_id: int, asset_id: int, tags: str) -> dict:
    """
    This endpoint sets the tags of a single asset in an Agentic Red Team (ART) project (replaces the asset's tag set).

    Args:
        art_id (int): The id of the Agentic Red Team project.
        asset_id (int): The id of the asset; retrieve valid ids via the `GetAssets` endpoint.
        tags (str): Comma-separated list of tag names to assign, e.g. "prod,staging"; unknown names are auto-created. Replaces the asset's current tag set.

    Returns:
        dict
    """
    path = "AddTagsToAsset"
    data = {
        "art_id": art_id,
        "asset_id": asset_id,
        "tags": tags,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def create_tag(art_id: int, name: str) -> dict:
    """
    This endpoint creates a new asset tag in an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        name (str): The name of the new tag.

    Returns:
        dict
    """
    path = "CreateTag"
    data = {
        "art_id": art_id,
        "name": name,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def delete_tag(art_id: int, tag_id: int) -> dict:
    """
    This endpoint deletes an asset tag from an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        tag_id (int): The id of the tag to delete; retrieve valid ids via the `GetTags` endpoint.

    Returns:
        dict
    """
    path = "DeleteTag"
    data = {
        "art_id": art_id,
        "tag_id": tag_id,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def edit_tags(art_id: int, asset_ids: str, tag_id: int) -> dict:
    """
    This endpoint bulk-applies a single tag to multiple assets in an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        asset_ids (str): Comma-separated list of asset ids to tag, e.g. "1,2,3"; retrieve valid ids via the `GetAssets` endpoint.
        tag_id (int): The id of the tag to apply; retrieve valid ids via the `GetTags` endpoint.

    Returns:
        dict
    """
    path = "EditTags"
    data = {
        "art_id": art_id,
        "asset_ids": asset_ids,
        "tag_id": tag_id,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def get_assets_scope(art_id: int, scope: str | None = None) -> dict:
    """
    This endpoint returns the scope configuration of the assets in an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        scope (str, optional): Scope selector to read; defaults to "".

    Returns:
        dict
    """
    path = "GetAssetsScope"
    data = {
        "art_id": art_id,
        "scope": scope,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def set_assets_scope(art_id: int, scope: str, asset_ids: str) -> dict:
    """
    This endpoint sets the scope configuration for one or more assets in an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        scope (str): The scope payload to apply.
        asset_ids (str): Comma-separated list of asset ids the scope applies to, e.g. "1,2,3"; retrieve valid ids via the `GetAssets` endpoint.

    Returns:
        dict
    """
    path = "SetAssetsScope"
    data = {
        "art_id": art_id,
        "scope": scope,
        "asset_ids": asset_ids,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def increase_priority_task(art_id: int, asset_id: int, action: str | None = None) -> dict:
    """
    This endpoint raises the scan priority of a single asset in an Agentic Red Team (ART) project ("run next") and wakes the dispatcher.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        asset_id (int): The id of the asset to prioritize; retrieve valid ids via the `GetAssets` endpoint.
        action (str, optional): The action/phase to prioritize (e.g. recon/blackbox/graybox/asm); defaults to "".

    Returns:
        dict
    """
    path = "IncreasePriorityTask"
    data = {
        "art_id": art_id,
        "asset_id": asset_id,
        "action": action,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def disable_scan_perm(art_id: int, scan_type: str, disable: bool) -> dict:
    """
    This endpoint enables or disables a scan type for an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        scan_type (str): The scan type to toggle; one of "recon", "blackbox", "graybox", "asm", "api".
        disable (bool): Set to True to disable the scan type, False to enable it.

    Returns:
        dict
    """
    path = "DisableScanPerm"
    data = {
        "art_id": art_id,
        "scan_type": scan_type,
        "disable": disable,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def start_asset_action(art_id: int, asset_id: int, action_type: str) -> dict:
    """
    This endpoint manually starts a scan action on a single asset in an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        asset_id (int): The id of the asset; retrieve valid ids via the `GetAssets` endpoint.
        action_type (str): The action/phase to start (e.g. recon/blackbox/graybox/asm/api).

    Returns:
        dict
    """
    path = "StartAssetAction"
    data = {
        "art_id": art_id,
        "asset_id": asset_id,
        "action_type": action_type,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def clear_asset_context(art_id: int, asset_id: int, include_vuln: bool | None = None, only_ai: bool | None = None) -> dict:
    """
    This endpoint clears the accumulated scan context of a single asset in an Agentic Red Team (ART) project. WARNING: this also wipes the asset's stored S3 artifacts, and (optionally) its vulnerabilities. When only_ai=True, only AI pause artifacts and AI-inserted vulnerabilities are removed.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        asset_id (int): The id of the asset; retrieve valid ids via the `GetAssets` endpoint.
        include_vuln (bool, optional): Set to True to also delete the asset's vulnerabilities; defaults to False. Ignored when only_ai=True.
        only_ai (bool, optional): Set to True to delete only AI-inserted vulnerabilities and AI pause S3 artifacts (hackerai/codeai/infraai); defaults to False.

    Returns:
        dict
    """
    path = "ClearAssetContext"
    data = {
        "art_id": art_id,
        "asset_id": asset_id,
        "include_vuln": include_vuln,
        "only_ai": only_ai,
    }
    return _post_json(path, _compact(data))


# --------------------------------------------------------------------------- #
# Activity / Queue
# --------------------------------------------------------------------------- #
@mcp.tool()
def get_last_activities(art_id: int, queue: bool | None = None) -> dict:
    """
    This endpoint returns the recent activity / queue feed of an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        queue (bool, optional): Set to True to return the queued tasks instead of the recent-activity feed; defaults to False.

    Returns:
        dict
    """
    path = "GetLastActivities"
    data = {
        "art_id": art_id,
        "queue": queue,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def skip_queue_activity(art_id: int, asset_id: int, task_id: int) -> dict:
    """
    This endpoint skips a single queued task in an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        asset_id (int): The id of the asset the queued task belongs to.
        task_id (int): The id of the queued task to skip; retrieve valid ids via `get_last_activities` with queue=True.

    Returns:
        dict
    """
    path = "SkipQueueActivity"
    data = {
        "art_id": art_id,
        "asset_id": asset_id,
        "task_id": task_id,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def prioritize_queue_activity(art_id: int, asset_id: int, task_id: int) -> dict:
    """
    This endpoint prioritizes a single queued task in an Agentic Red Team (ART) project so it runs next.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        asset_id (int): The id of the asset the queued task belongs to.
        task_id (int): The id of the queued task to prioritize; retrieve valid ids via `get_last_activities` with queue=True.

    Returns:
        dict
    """
    path = "PrioritizeQueueActivity"
    data = {
        "art_id": art_id,
        "asset_id": asset_id,
        "task_id": task_id,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def clean_queue(art_id: int) -> dict:
    """
    This endpoint clears all queued tasks of an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.

    Returns:
        dict
    """
    path = "CleanQueue"
    data = {
        "art_id": art_id,
    }
    return _post_json(path, _compact(data))


# --------------------------------------------------------------------------- #
# Recommendations (Actions)
# --------------------------------------------------------------------------- #
@mcp.tool()
def get_art_actions(art_id: int, limit: int = 20, offset: int = 0, filter_via_tags: str | None = None) -> dict:
    """
    This endpoint lists the recommended remediation actions of an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        limit (int, optional): Page size; defaults to 20.
        offset (int, optional): Number of rows to skip for pagination; defaults to 0.
        filter_via_tags (str, optional): Comma-separated list of tag ids to filter by, e.g. "1,2"; defaults to no filter.

    Returns:
        dict
    """
    path = "GetArtActions"
    data = {
        "art_id": art_id,
        "limit": limit,
        "offset": offset,
        "filter_via_tags": filter_via_tags,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def ignore_art_action(art_id: int, action_id: int, asset_id: int = 0, skip: bool | None = None) -> dict:
    """
    This endpoint ignores or un-ignores a recommended action in an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        action_id (int): The id of the action; retrieve valid ids via the `GetArtActions` endpoint.
        asset_id (int, optional): The id of the asset the action belongs to; defaults to 0 (not asset-scoped).
        skip (bool, optional): Set to True to ignore the action, False to un-ignore it; defaults to True.

    Returns:
        dict
    """
    path = "IgnoreArtAction"
    data = {
        "art_id": art_id,
        "action_id": action_id,
        "asset_id": asset_id,
        "skip": skip,
    }
    return _post_json(path, _compact(data))


# --------------------------------------------------------------------------- #
# Users / Members
# --------------------------------------------------------------------------- #
@mcp.tool()
def add_art_user(art_id: int, user_id_to_set: int, role: str) -> dict:
    """
    This endpoint adds an existing tenant user as a member of an Agentic Red Team (ART) project. Admin only.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        user_id_to_set (int): The id of the user to add as a member; retrieve valid ids via the `GetUsers` endpoint.
        role (str): The membership role; one of "Viewer" or "Editor".

    Returns:
        dict
    """
    path = "AddArtUser"
    data = {
        "art_id": art_id,
        "user_id_to_set": user_id_to_set,
        "role": role,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def edit_art_user(art_id: int, user_id_to_set: int, role: str) -> dict:
    """
    This endpoint changes the role of an existing member of an Agentic Red Team (ART) project. Admin only.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        user_id_to_set (int): The id of the member to update; retrieve valid ids via the `GetArtUsers` endpoint.
        role (str): The new role; one of "Viewer" or "Editor".

    Returns:
        dict
    """
    path = "EditArtUser"
    data = {
        "art_id": art_id,
        "user_id_to_set": user_id_to_set,
        "role": role,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def get_art_users(art_id: int) -> dict:
    """
    This endpoint lists the members of an Agentic Red Team (ART) project and their roles.

    Args:
        art_id (int): The id of the Agentic Red Team project.

    Returns:
        dict
    """
    path = "GetArtUsers"
    data = {
        "art_id": art_id,
    }
    return _post_json(path, _compact(data))


# --------------------------------------------------------------------------- #
# Chat Assistant
# --------------------------------------------------------------------------- #
@mcp.tool()
def get_chat_messages(art_id: int) -> dict:
    """
    This endpoint returns the chat history of the Agentic Red Team (ART) assistant for a project. Requires the chat assistant to be enabled for the tenant.

    Args:
        art_id (int): The id of the Agentic Red Team project.

    Returns:
        dict
    """
    path = "GetChatMessages"
    data = {
        "art_id": art_id,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def send_chat_message(art_id: int, message: str, mode: str | None = None) -> dict:
    """
    This endpoint sends a message to the Agentic Red Team (ART) chat assistant for a project. Requires the chat assistant to be enabled for the tenant.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        message (str): The message text to send.
        mode (str, optional): The chat mode; one of "ask" (read-only) or "agent" (can take actions); defaults to "ask".

    Returns:
        dict
    """
    path = "SendChatMessage"
    data = {
        "art_id": art_id,
        "message": message,
        "mode": mode,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def report_chat_message(art_id: int, message_id: int, report_info: str) -> dict:
    """
    This endpoint reports/flags a specific Agentic Red Team (ART) chat assistant message.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        message_id (int): The id of the chat message to report; retrieve valid ids via the `GetChatMessages` endpoint.
        report_info (str): A description of the issue being reported.

    Returns:
        dict
    """
    path = "ReportChatMessage"
    data = {
        "art_id": art_id,
        "message_id": message_id,
        "report_info": report_info,
    }
    return _post_json(path, _compact(data))


# --------------------------------------------------------------------------- #
# Configurations (generic)
#
# CONF_TYPES — the full set of `conf_type` values the ART configuration tools
# understand. Use this as the reference for what to pass as `conf_type` to
# add_configuration / edit_configuration, what to filter on in get_configurations
# (conf_types), and what disable_configuration accepts. Most types have a
# dedicated typed tool (shown in parentheses); the rest go through the generic
# add_configuration with a `connector_id` you look up first.
#
#   "authentication"   - primary login profile           (add_auth_configuration / edit_auth_configuration)
#   "basic"            - HTTP Basic / NTLM login          (add_auth_configuration, via action_basic)
#   "rate_limit"       - max requests-per-second + timeout (add_rate_limit_configuration)
#   "headers"          - custom request headers            (add_headers_cookies_configuration, conf_type="headers")
#   "cookies"          - custom request cookies            (add_headers_cookies_configuration, conf_type="cookies")
#   "include_only"     - scope allow-list (paths/hosts)    (add_include_only_configuration)
#   "art_hosts_file"   - hosts-file [ip, domain] mappings  (set_art_hosts_file)
#   "attach_files"     - attached file group               (add_art_group_files_configuration)
#   "crt"              - client certificate / mTLS          (add_certificates_configuration)
#   "scan_time_window" - allowed scanning hours/days        (add_time_window_configuration)
#   "ai_actions"       - AI-action template                 (add_ai_actions)
#   "custom_payloads"  - ART custom payload connector data  (add_custom_payloads_configuration)
#   "broker"           - OpenZiti broker / proxy            (add_configuration; connector_id from get_brokers)
#   "fixed_ip"         - static source IP                   (add_configuration; connector_id from get_all_fixed_ip)
#   "attack_profile"   - reusable attack profile            (add_configuration; connector_id from get_all_attack_profile)
#   "api_schema"       - uploaded API schema (OpenAPI/Swagger) (add_configuration; connector_id is the uploaded file id)
#   "jira" / "monday" / "azure" / "slack" - ticketing / notification integration bindings
#                        (add_configuration; connector_id is the integration's id)
# --------------------------------------------------------------------------- #
ART_CONF_TYPES = (
    "authentication, basic, rate_limit, headers, cookies, include_only, art_hosts_file, "
    "attach_files, crt, scan_time_window, ai_actions, custom_payloads, broker, fixed_ip, "
    "attack_profile, api_schema, jira, monday, azure, slack"
)


@mcp.tool()
def add_configuration(art_id: int, name: str, conf_type: str, connector_id: int, asset_ids: str) -> dict:
    """
    This endpoint links an existing connector to assets of an Agentic Red Team (ART) project by creating a named configuration row. It does not create the connector itself, so `connector_id` must already point at a row of the requested `conf_type`, otherwise the call is rejected.

    Use it for the types that have no dedicated endpoint of their own: 'broker', 'fixed_ip', 'attack_profile', 'api_schema', 'jira', 'monday', 'azure' and 'slack'. Every other type is created together with its connector by a typed endpoint instead: `AddAuthConfiguration` ('authentication' / 'basic'), `AddRateLimitConfiguration` ('rate_limit'), `AddHeadersCookiesConfiguration` ('headers' / 'cookies'), `AddIncludeOnlyConfiguration` ('include_only'), `SetArtHostsFile` ('art_hosts_file'), `AddArtGroupFilesConfiguration` ('attach_files'), `AddCertificatesConfiguration` ('crt'), `AddTimeWindowConfiguration` ('scan_time_window'), `AddAiActions` ('ai_actions') and `AddCustomPayloadsConfiguration` ('custom_payloads').

    Where to read `connector_id` from, per conf_type:
            - 'broker' -> the id of a broker, from the `GetBrokers` endpoint.
            - 'fixed_ip' -> the id of a fixed IP, from the `GetAllFixedIP` endpoint.
            - 'attack_profile' -> the id of an attack profile, from the `GetAllAttackProfile` endpoint.
            - 'api_schema' -> the id of an uploaded schema file, from the `GetFiles` endpoint with category='api_schema'.
            - 'jira' / 'monday' / 'azure' / 'slack' -> the id of the integration; from the `GetAllSlack` endpoint for Slack, while `GetAllJira`, `GetAllMonday` and `GetAllAzure` list the connected projects by name only, so take the id of those from the UI.

    Args:
        art_id (int): The id of the Agentic Red Team project the configuration belongs to; retrieve valid ids via the `GetArtProjects` endpoint.
        name (str): A descriptive name for the configuration, e.g. 'Production broker'. It must be unique among the configurations of that type in the project.
        conf_type (str): The type of configuration to create; one of 'broker', 'fixed_ip', 'attack_profile', 'api_schema', 'jira', 'monday', 'azure' or 'slack'.
        connector_id (int): The id of the existing connector row this configuration points at; see the list above for where to read it from.
        asset_ids (str): Comma-separated list of asset ids the configuration applies to, e.g. '1,2,3'; at least one id is required. Retrieve valid ids via the `GetAssets` endpoint.

    Returns:
        dict
    """
    path = "AddConfiguration"
    data = {
        "art_id": art_id,
        "name": name,
        "conf_type": conf_type,
        "connector_id": connector_id,
        "asset_ids": asset_ids,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def get_configurations(art_id: int, conf_types: str | None = None) -> dict:
    """
    This endpoint lists the configurations of an Agentic Red Team (ART) project, optionally filtered by type.
    Each returned configuration includes its `value` for value-bearing types (e.g. the hosts list for
    "art_hosts_file", the custom-payloads connector data, the headers/cookies payload, the rate-limit
    settings, the include-only scope, ...).

    Valid conf_type values to filter on (full catalog):
        authentication, basic, rate_limit, headers, cookies, include_only, art_hosts_file,
        attach_files, crt, scan_time_window, ai_actions, custom_payloads, broker, fixed_ip,
        attack_profile, api_schema, jira, monday, azure, slack

    Args:
        art_id (int): The id of the Agentic Red Team project.
        conf_types (str, optional): Comma-separated list of configuration types to filter by,
            e.g. "rate_limit,headers" or "art_hosts_file"; defaults to "" (return all types).

    Returns:
        dict
    """
    path = "GetConfigurations"
    data = {
        "art_id": art_id,
        "conf_types": conf_types,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def edit_configuration(art_id: int, conf_id: int, name: str, conf_type: str, connector_id: int, asset_ids: str) -> dict:
    """
    This endpoint edits a configuration created by `AddConfiguration`: it renames it, points it at a different connector, or changes which assets it applies to.

    Every argument is a replacement, not a partial update, so send the full desired state: whatever you pass in `name`, `conf_type` and `connector_id` overwrites the row, and `asset_ids` becomes the complete asset list (assets missing from it are unlinked, and an empty value unlinks all of them). Read the current values with `GetConfigurations` first and resend the ones you do not want to change.

    Use it for the same types as `AddConfiguration`: 'broker', 'fixed_ip', 'attack_profile', 'api_schema', 'jira', 'monday', 'azure' and 'slack'. Every other type has its own endpoint: `EditAuthConfiguration` ('authentication' / 'basic'), `EditRateLimitConfiguration` ('rate_limit'), `EditHeadersCookiesConfiguration` ('headers' / 'cookies'), `EditIncludeOnlyConfiguration` ('include_only'), `SetArtHostsFile` ('art_hosts_file'), `EditArtGroupFilesConfiguration` ('attach_files'), `EditCertificatesConfiguration` ('crt'), `EditTimeWindowConfiguration` ('scan_time_window') and `EditCustomPayloadsConfiguration` ('custom_payloads').

    Where to read `connector_id` from, per conf_type:
            - 'broker' -> the id of a broker, from the `GetBrokers` endpoint.
            - 'fixed_ip' -> the id of a fixed IP, from the `GetAllFixedIP` endpoint.
            - 'attack_profile' -> the id of an attack profile, from the `GetAllAttackProfile` endpoint.
            - 'api_schema' -> the id of an uploaded schema file, from the `GetFiles` endpoint with category='api_schema'.
            - 'jira' / 'monday' / 'azure' / 'slack' -> the id of the integration; from the `GetAllSlack` endpoint for Slack, while `GetAllJira`, `GetAllMonday` and `GetAllAzure` list the connected projects by name only, so take the id of those from the UI.

    Args:
        art_id (int): The id of the Agentic Red Team project that owns the configuration; retrieve valid ids via the `GetArtProjects` endpoint.
        conf_id (int): The id of the configuration to edit; retrieve valid ids via the `GetConfigurations` endpoint. It must belong to `art_id`, otherwise the call is rejected.
        name (str): The new name for the configuration. It must stay unique among the configurations of that type in the project.
        conf_type (str): The type of the configuration; one of 'broker', 'fixed_ip', 'attack_profile', 'api_schema', 'jira', 'monday', 'azure' or 'slack'.
        connector_id (int): The id of the connector the configuration should point at after the edit; resend the current one to keep it, or a different one to swap it. See the list above for where to read it from.
        asset_ids (str): The complete comma-separated list of asset ids the configuration should apply to, e.g. '1,2,3'; retrieve valid ids via the `GetAssets` endpoint.

    Returns:
        dict
    """
    path = "EditConfiguration"
    data = {
        "art_id": art_id,
        "conf_id": conf_id,
        "name": name,
        "conf_type": conf_type,
        "connector_id": connector_id,
        "asset_ids": asset_ids,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def delete_configuration(art_id: int, conf_id: int) -> dict:
    """
    This endpoint deletes a configuration from an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        conf_id (int): The id of the configuration to delete; retrieve valid ids via the `GetConfigurations` endpoint.

    Returns:
        dict
    """
    path = "DeleteConfiguration"
    data = {
        "art_id": art_id,
        "conf_id": conf_id,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def skip_configuration(art_id: int, conf_id: int, skip: bool) -> dict:
    """
    This endpoint toggles the "skip" flag of a single configuration in an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        conf_id (int): The id of the configuration; retrieve valid ids via the `GetConfigurations` endpoint.
        skip (bool): Set to True to skip the configuration, False to stop skipping it.

    Returns:
        dict
    """
    path = "SkipConfiguration"
    data = {
        "art_id": art_id,
        "conf_id": conf_id,
        "skip": skip,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def validate_configuration(art_id: int, conf_id: int) -> dict:
    """
    This endpoint validates a single configuration in an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        conf_id (int): The id of the configuration to validate; retrieve valid ids via the `GetConfigurations` endpoint.

    Returns:
        dict
    """
    path = "ValidateConfiguration"
    data = {
        "art_id": art_id,
        "conf_id": conf_id,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def disable_configuration(art_id: int, conf_type: str, disable_conf: bool) -> dict:
    """
    This endpoint enables or disables an entire configuration type for an Agentic Red Team (ART) project.

    Valid conf_type values (full catalog):
        authentication, basic, rate_limit, headers, cookies, include_only, art_hosts_file,
        attach_files, crt, scan_time_window, ai_actions, custom_payloads, broker, fixed_ip,
        attack_profile, api_schema, jira, monday, azure, slack

    Args:
        art_id (int): The id of the Agentic Red Team project.
        conf_type (str): The configuration type to toggle (see the full catalog above), e.g. "rate_limit", "headers", "art_hosts_file", "custom_payloads".
        disable_conf (bool): Set to True to disable the configuration type, False to enable it.

    Returns:
        dict
    """
    path = "DisableConfiguration"
    data = {
        "art_id": art_id,
        "conf_type": conf_type,
        "disable_conf": disable_conf,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def get_configuration_assets(art_id: int, conf_id: int) -> dict:
    """
    This endpoint returns the assets a single configuration is applied to in an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        conf_id (int): The id of the configuration; retrieve valid ids via the `GetConfigurations` endpoint.

    Returns:
        dict
    """
    path = "GetConfigurationAssets"
    data = {
        "art_id": art_id,
        "conf_id": conf_id,
    }
    return _post_json(path, _compact(data))


# --------------------------------------------------------------------------- #
# Configuration connectors - Authentication
# --------------------------------------------------------------------------- #
@mcp.tool()
def add_auth_configuration(art_id: int, name: str, action: str, asset_ids: str, username: str | None = None,
                           password: str | None = None, prompt: str | None = None,
                           data: dict | str | None = None,
                           params: str | None = None, otp_email: int = 0, otp_phone_number: int = 0,
                           auth_secret_key: str | None = None, connector_id: int = 0, action_basic: str | None = None,
                           basic_username: str | None = None, basic_password: str | None = None,
                           basic_connector_id: int = 0) -> dict:
    """
    This endpoint creates a login (authentication) configuration and attaches it to one or more assets in an Agentic Red Team (ART) project. The scanner uses it to log in to those assets before testing them.

    Pick ONE of three ways to provide the login:
            1. Reuse an existing saved login -> list the saved login profiles with the `GetLogins` endpoint, set `connector_id` to the id of the one you want and leave the credential fields empty.
            2. AI-driven login ('log_ai') -> recommended for web app logins. Put the credentials in `data` and an optional human instruction in `prompt`.
            3. Dialog login ('log_d' / 'log_ntlm') -> classic HTTP Basic / NTLM popup. Put the credentials in the top-level `username` / `password` fields.

    Security note: avoid sending real production credentials when you can. Prefer reusing an existing login via `connector_id`, or the AI flow with a `prompt`, over raw username/password.

    Args:
        art_id (int): The id of the Agentic Red Team project that owns the assets; retrieve valid ids via the `GetArtProjects` endpoint.
        name (str): A descriptive name for this login, e.g. 'Admin portal login'.
        action (str): How the login works. Must be exactly one of:
                - 'log_ai' -> AI-driven web login (recommended).
                - 'log_d' -> Login Dialog / HTTP Basic.
                - 'log_ntlm' -> NTLM dialog login. 
        asset_ids (str): Comma-separated list of asset ids the login applies to, e.g. '1,2,3'; retrieve valid ids via the `GetAssets` endpoint.
        username (str, optional): The username, only for 'log_d' / 'log_ntlm'. Required (non-empty) when creating a new login (`connector_id=0`). Leave empty for 'log_ai' (its credentials live inside `data`) or when reusing `connector_id`.
        password (str, optional): The password, only for 'log_d' / 'log_ntlm'. Required (non-empty) when creating a new login (`connector_id=0`). Leave empty for 'log_ai' or when reusing `connector_id`.
        prompt (str, optional): For 'log_ai' only. A plain-text natural-language instruction telling the AI how to log in, e.g. 'Go to /login, fill the email and password fields, then click Sign in'.
        data (dict | str, optional): For 'log_ai' only. The credentials and options as a JSON object, e.g. {'username': 'admin', 'password': 'admin'}; pass a dict (preferred) or an equivalent JSON string. Common keys are 'username', 'password', 'otp' (e.g. 'Login OTP SMS', 'Google Authenticator', 'Okta Authenticator') and 'last_digits' (last 4 phone digits for SMS OTP); extra keys are kept. Required when creating a new login (`connector_id=0`), and every key in it must have a non-empty value.
        params (str, optional): JSON array of extra form parameters for the login; defaults to '[]'.
        otp_email (int, optional): The id of a registered OTP email to use; leave it empty if the login does not use an email OTP. Retrieve valid ids via the `GetAllEmails` endpoint, and register the address in the UI first if it is missing.
        otp_phone_number (int, optional): The id of a registered OTP phone number to use; leave it empty if the login does not use an SMS OTP. Retrieve valid ids via the `GetAllPhones` endpoint, and register the number in the UI first if it is missing.
        auth_secret_key (str, optional): TOTP shared secret for authenticator-based logins (Google / Microsoft / Okta Authenticator), used with 'log_ai'.
        connector_id (int, optional): The id of an existing saved login profile to reuse instead of supplying new credentials, 0 to create a new one; retrieve valid ids via the `GetLogins` endpoint. Its `type_login` must match `action`: 'Login Dialog' / 'NTLM Dialog' for 'log_d' / 'log_ntlm', any other type for 'log_ai'.
        action_basic (str, optional): Adds a second login alongside a 'log_ai' primary; must be 'log_d' or 'log_ntlm', and the primary `action` must be 'log_ai'. Empty for a single login.
        basic_username (str, optional): The username for the optional second (basic) login.
        basic_password (str, optional): The password for the optional second (basic) login.
        basic_connector_id (int, optional): The id of an existing saved login profile to reuse for the optional second login, 0 to create a new one; retrieve valid ids via the `GetLogins` endpoint, and pick one whose `type_login` is 'Login Dialog' or 'NTLM Dialog'.

    Returns:
        dict
    """
    path = "AddAuthConfiguration"
    payload = {
        "art_id": art_id,
        "name": name,
        "action": action,
        "asset_ids": asset_ids,
        "username": username,
        "password": password,
        "prompt": prompt,
        "data": data,
        "params": params,
        "otp_email": otp_email,
        "otp_phone_number": otp_phone_number,
        "auth_secret_key": auth_secret_key,
        "connector_id": connector_id,
        "action_basic": action_basic,
        "basic_username": basic_username,
        "basic_password": basic_password,
        "basic_connector_id": basic_connector_id,
    }
    return _post_json(path, _compact(payload))


@mcp.tool()
def edit_auth_configuration(art_id: int, conf_id: int, name: str, action: str, asset_ids: str,
                            username: str | None = None, password: str | None = None, prompt: str | None = None,
                            data: dict | str | None = None, params: str | None = None, otp_email: int = 0,
                            otp_phone_number: int = 0, auth_secret_key: str | None = None, connector_id: int = 0,
                            old_connector_id: int = 0, action_basic: str | None = None,
                            basic_username: str | None = None, basic_password: str | None = None,
                            basic_connector_id: int = 0, basic_conf_id: int | None = None,
                            basic_old_connector_id: int = 0, basic_has_changed: bool | str | None = None) -> dict:
    """
    This endpoint edits an existing login (authentication) configuration in an Agentic Red Team (ART) project: its name, credentials, linked assets, or which saved login backs it.

    The credential fields work exactly like `add_auth_configuration` and are chosen by `action`:
            - 'log_ai' -> AI-driven web login. Put the credentials in `data` and an optional instruction in `prompt`.
            - 'log_d' -> Login Dialog / HTTP Basic. Put the credentials in `username` + `password`.
            - 'log_ntlm' -> NTLM dialog login. Put the credentials in `username` + `password`.

    Dual Login AI + HTTP Basic/NTLM: `basic_has_changed` controls the sibling `basic` configuration:
            - omitted / false -> leave the sibling unchanged (even if leftover basic_* fields are present).
            - true + `action_basic` (`log_d` or `log_ntlm`) and `basic_conf_id` / `basic_connector_id` -> update the existing basic half.
            - true without `action_basic` -> delete the basic configuration row (and its ART-owned login). Do not use `delete_configuration` for that; it would also delete the Login AI half.

    To keep the current credentials unchanged, simply omit them. Security note: prefer reusing an existing login via `connector_id` over re-sending credentials, and prefer the AI flow ('log_ai') with a `prompt` over raw username/password.

    Args:
        art_id (int): The id of the Agentic Red Team project that owns the configuration; retrieve valid ids via the `GetArtProjects` endpoint.
        conf_id (int): The id of the login configuration to edit; retrieve valid ids via the `GetConfigurations` endpoint with conf_types='authentication,basic'.
        name (str): A descriptive name for this login.
        action (str): How the login works. Must be exactly one of:
                - 'log_ai' -> AI-driven web login. The credentials go in `data`.
                - 'log_d' -> Login Dialog / HTTP Basic. The credentials go in `username` + `password`.
                - 'log_ntlm' -> NTLM dialog login. The credentials go in `username` + `password`.
        asset_ids (str): Comma-separated list of asset ids the login applies to, e.g. '1,2,3'; retrieve valid ids via the `GetAssets` endpoint.
        username (str, optional): The username, only for 'log_d' / 'log_ntlm'. Omit to keep it unchanged.
        password (str, optional): The password, only for 'log_d' / 'log_ntlm'. Omit to keep it unchanged.
        prompt (str, optional): For 'log_ai' only. A plain-text natural-language login instruction. Do not encode it.
        data (dict | str, optional): For 'log_ai' only. The credentials and options as a JSON object, e.g. {'username': 'admin', 'password': 'admin'}.
        params (str, optional): JSON array of extra form parameters for the login; defaults to '[]'.
        otp_email (int, optional): The id of a registered OTP email to use; leave it empty if the login does not use an email OTP. Retrieve valid ids via the `GetAllEmails` endpoint.
        otp_phone_number (int, optional): The id of a registered OTP phone number to use; leave it empty if the login does not use an SMS OTP. Retrieve valid ids via the `GetAllPhones` endpoint.
        auth_secret_key (str, optional): TOTP shared secret for authenticator-based logins, used with 'log_ai'.
        connector_id (int, optional): The id of the saved login profile that backs this configuration, 0 for none; retrieve valid ids via the `GetLogins` endpoint. Its `type_login` must match `action`: 'Login Dialog' / 'NTLM Dialog' for 'log_d' / 'log_ntlm', any other type for 'log_ai'.
        old_connector_id (int, optional): The previous backing login id; set it when switching to a different saved login so the old link is replaced, 0 when there is no switch. It is the `connector_id` the configuration currently has in the `GetConfigurations` response.
        action_basic (str, optional): The second (basic) login's method when updating a dual login, 'log_d' or 'log_ntlm'. Omit with `basic_has_changed=true` to delete that half.
        basic_username (str, optional): The username for the optional second (basic) login.
        basic_password (str, optional): The password for the optional second (basic) login.
        basic_connector_id (int, optional): The id of the saved login profile backing the optional second (basic) login; retrieve valid ids via the `GetLogins` endpoint, and pick one whose `type_login` is 'Login Dialog' or 'NTLM Dialog'.
        basic_conf_id (int, optional): The configuration id of the optional second (basic) login; retrieve valid ids via the `GetConfigurations` endpoint with conf_types='basic'. Required when updating the basic half.
        basic_old_connector_id (int, optional): The previous backing login id for the second login when switching it to a different saved login; it is the `connector_id` that configuration currently has in the `GetConfigurations` response.
        basic_has_changed (bool | str, optional): true when the Basic/NTLM sibling should be updated or deleted. false or omitted leaves the sibling as-is.

    Returns:
        dict
    """
    path = "EditAuthConfiguration"
    payload = {
        "art_id": art_id,
        "conf_id": conf_id,
        "name": name,
        "action": action,
        "asset_ids": asset_ids,
        "username": username,
        "password": password,
        "prompt": prompt,
        "data": data,
        "params": params,
        "otp_email": otp_email,
        "otp_phone_number": otp_phone_number,
        "auth_secret_key": auth_secret_key,
        "connector_id": connector_id,
        "old_connector_id": old_connector_id,
        "action_basic": action_basic,
        "basic_username": basic_username,
        "basic_password": basic_password,
        "basic_connector_id": basic_connector_id,
        "basic_conf_id": basic_conf_id,
        "basic_old_connector_id": basic_old_connector_id,
        "basic_has_changed": basic_has_changed,
    }
    return _post_json(path, _compact(payload))


@mcp.tool()
def get_art_login(art_id: int, login_id: int, asset_id: int) -> dict:
    """
    This endpoint returns the login-check result the scanner produced for one saved login on one asset of an Agentic Red Team (ART) project. Credentials are never returned.

    Each returned row contains:
            - status -> the state of the check: 'Pending', 'Initiating', 'In Progress', 'Paused', 'Completed' or 'Aborted'.
            - event_log -> the step-by-step log of the login attempt.
            - login_image, data_image, login_gif -> the captures taken while logging in.

    Args:
        art_id (int): The id of the Agentic Red Team project that owns the asset; retrieve valid ids via the `GetArtProjects` endpoint. It is mandatory.
        login_id (int): The id of the login whose check should be read; take it from the `connector_id` field of the login configuration returned by the `GetConfigurations` endpoint with conf_types='authentication,basic'.
        asset_id (int): The id of the asset the login was checked against; take it from the `asset_ids` of that same configuration row, or retrieve valid ids via the `GetAssets` endpoint.

    Returns:
        dict
    """
    path = "GetArtLogin"
    data = {
        "art_id": art_id,
        "login_id": login_id,
        "asset_id": asset_id,
    }
    return _post_json(path, _compact(data))


# --------------------------------------------------------------------------- #
# Configuration connectors - Rate Limits
# --------------------------------------------------------------------------- #
@mcp.tool()
def add_rate_limit_configuration(art_id: int, name: str, rps: int, timeout: float, asset_ids: str) -> dict:
    """
    This endpoint creates a rate-limit configuration for assets in an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        name (str): A descriptive name for the configuration.
        rps (int): Maximum requests per second the scanner may send.
        timeout (float): Per-request timeout in seconds.
        asset_ids (str): Comma-separated list of asset ids the configuration applies to, e.g. "1,2,3".

    Returns:
        dict
    """
    path = "AddRateLimitConfiguration"
    data = {
        "art_id": art_id,
        "name": name,
        "rps": rps,
        "timeout": timeout,
        "asset_ids": asset_ids,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def edit_rate_limit_configuration(art_id: int, conf_id: int, connector_id: int, name: str, rps: int, timeout: float,
                                  asset_ids: str) -> dict:
    """
    This endpoint edits a rate-limit configuration in an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        conf_id (int): The id of the configuration to edit; retrieve valid ids via the `GetConfigurations` endpoint.
        connector_id (int): The id of the backing rate-limit connector row.
        name (str): A descriptive name for the configuration.
        rps (int): Maximum requests per second the scanner may send.
        timeout (float): Per-request timeout in seconds.
        asset_ids (str): Comma-separated list of asset ids the configuration applies to, e.g. "1,2,3".

    Returns:
        dict
    """
    path = "EditRateLimitConfiguration"
    data = {
        "art_id": art_id,
        "conf_id": conf_id,
        "connector_id": connector_id,
        "name": name,
        "rps": rps,
        "timeout": timeout,
        "asset_ids": asset_ids,
    }
    return _post_json(path, _compact(data))


# --------------------------------------------------------------------------- #
# Configuration connectors - Headers & Cookies
# --------------------------------------------------------------------------- #
@mcp.tool()
def add_headers_cookies_configuration(art_id: int, conf_type: str, value: dict | list | str, name: str,
                                      asset_ids: str) -> dict:
    """
    This endpoint creates a headers or cookies configuration for assets in an Agentic Red Team (ART) project. The scanner then sends those headers or cookies with every request it makes to the linked assets.

    Args:
        art_id (int): The id of the Agentic Red Team project the configuration belongs to; retrieve valid ids via the `GetArtProjects` endpoint.
        conf_type (str): What the payload holds; one of 'headers' or 'cookies'.
        value (dict): The payload as a JSON object mapping each header/cookie name to its value, e.g. {'X-Api-Key': 'abc'}. A JSON array of single-pair objects such as [{'X-Api-Key': 'abc'}, {'X-Env': 'prod'}] is accepted too and is flattened into one object, and so is a JSON-encoded string of either form. It must not be empty, and the values cannot contain control characters, quotes or angle brackets.
        name (str): A descriptive name for the configuration, e.g. 'Api key header'. It must be unique among the configurations of that type in the project.
        asset_ids (str): Comma-separated list of asset ids the configuration applies to, e.g. '1,2,3'; at least one id is required. Retrieve valid ids via the `GetAssets` endpoint.

    Returns:
        dict
    """
    path = "AddHeadersCookiesConfiguration"
    data = {
        "art_id": art_id,
        "conf_type": conf_type,
        "value": value,
        "name": name,
        "asset_ids": asset_ids,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def edit_headers_cookies_configuration(art_id: int, conf_id: int, connector_id: int, conf_type: str,
                                       value: dict | list | str, name: str, asset_ids: str) -> dict:
    """
    This endpoint edits a headers or cookies configuration in an Agentic Red Team (ART) project.

    Every argument is a replacement, not a partial update, so send the full desired state: `value` overwrites the whole payload rather than merging into it, and `asset_ids` becomes the complete asset list (assets missing from it are unlinked). Read the current values with `GetConfigurations` first and resend the ones you do not want to change.

    Args:
        art_id (int): The id of the Agentic Red Team project that owns the configuration; retrieve valid ids via the `GetArtProjects` endpoint.
        conf_id (int): The id of the configuration to edit; retrieve valid ids via the `GetConfigurations` endpoint with conf_types='headers,cookies'. It must belong to `art_id`, otherwise the call is rejected.
        connector_id (int): The id of the connector row that holds the payload; take the `connector_id` of the same configuration from the `GetConfigurations` response.
        conf_type (str): What the payload holds; one of 'headers' or 'cookies'.
        value (dict): The new payload as a JSON object mapping each header/cookie name to its value, e.g. {'X-Api-Key': 'abc'}. A JSON array of single-pair objects such as [{'X-Api-Key': 'abc'}, {'X-Env': 'prod'}] is accepted too and is flattened into one object, and so is a JSON-encoded string of either form. It must not be empty, and the values cannot contain control characters, quotes or angle brackets.
        name (str): The new name for the configuration. It must stay unique among the configurations of that type in the project.
        asset_ids (str): The complete comma-separated list of asset ids the configuration should apply to, e.g. '1,2,3'; retrieve valid ids via the `GetAssets` endpoint.

    Returns:
        dict
    """
    path = "EditHeadersCookiesConfiguration"
    data = {
        "art_id": art_id,
        "conf_id": conf_id,
        "connector_id": connector_id,
        "conf_type": conf_type,
        "value": value,
        "name": name,
        "asset_ids": asset_ids,
    }
    return _post_json(path, _compact(data))


# --------------------------------------------------------------------------- #
# Configuration connectors - Custom Payloads
# --------------------------------------------------------------------------- #
@mcp.tool()
def add_custom_payloads_configuration(art_id: int, name: str, payload_name: str | None = None,
                                      payload: str | None = None, src_result: str | None = None,
                                      severity: str | None = None, description: str | None = None,
                                      impact: str | None = None, recommendation: str | None = None,
                                      details: str | None = None, links: str | None = None,
                                      cwe: str | None = None, cvss: str | None = None) -> dict:
    """
    Creates an ART custom-payloads configuration.

    Flow: validate configuration name → build connector `data` via
    `_build_custom_payload_data` → INSERT `art_custom_payloads` →
    insert only the configuration metadata row (`custom_payloads`) with no asset links.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        name (str): A descriptive name for the configuration.
        payload_name (str, optional): Payload display name (`art_custom_payloads.name`).
        payload (str, optional): Payload content (`art_custom_payloads.payloads`).
        src_result (str, optional): Expected/source result string.
        severity (str, optional): One of informative, low, medium, high, or 0..3.
        description (str, optional): Vulnerability description.
        impact (str, optional): Impact text.
        recommendation (str, optional): Remediation recommendation.
        details (str, optional): Additional details (`more_details` column).
        links (str, optional): Reference links.
        cwe (str, optional): CWE identifier.
        cvss (str, optional): CVSS score/string.

    Returns:
        dict
    """
    path = "AddCustomPayloadsConfiguration"
    data = {
        "art_id": art_id,
        "name": name,
        "payload_name": payload_name,
        "payload": payload,
        "src_result": src_result,
        "severity": severity,
        "description": description,
        "impact": impact,
        "recommendation": recommendation,
        "details": details,
        "links": links,
        "cwe": cwe,
        "cvss": cvss,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def edit_custom_payloads_configuration(art_id: int, conf_id: int, connector_id: int, name: str,
                                       payload_name: str | None = None, payload: str | None = None,
                                       src_result: str | None = None, severity: str | None = None,
                                       description: str | None = None, impact: str | None = None,
                                       recommendation: str | None = None, details: str | None = None,
                                       links: str | None = None, cwe: str | None = None,
                                       cvss: str | None = None) -> dict:
    """
    Edits an ART custom-payloads configuration.

    Flow: verify `conf_id` / `connector_id` ownership → load `existing_data` from
    `art_custom_payloads` → merge submitted fields via `_build_custom_payload_data`
    → update the configuration metadata row (name/connector/type) without changing
    asset links → UPDATE connector row. Optional fields support partial update;
    pass "" to clear description, impact, recommendation, details, links, cwe, or cvss.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        conf_id (int): The id of the configuration to edit; retrieve valid ids via the `GetConfigurations` endpoint.
        connector_id (int): The id of the backing art_custom_payloads row.
        name (str): A descriptive name for the configuration.
        payload_name (str, optional): Payload display name.
        payload (str, optional): Payload content.
        src_result (str, optional): Expected/source result string.
        severity (str, optional): One of informative, low, medium, high, or 0..3.
        description (str, optional): Vulnerability description; pass "" to clear.
        impact (str, optional): Impact text; pass "" to clear.
        recommendation (str, optional): Remediation recommendation; pass "" to clear.
        details (str, optional): Additional details; pass "" to clear.
        links (str, optional): Reference links; pass "" to clear.
        cwe (str, optional): CWE identifier; pass "" to clear.
        cvss (str, optional): CVSS score/string; pass "" to clear.

    Returns:
        dict
    """
    path = "EditCustomPayloadsConfiguration"
    data = {
        "art_id": art_id,
        "conf_id": conf_id,
        "connector_id": connector_id,
        "name": name,
        "payload_name": payload_name,
        "payload": payload,
        "src_result": src_result,
        "severity": severity,
        "description": description,
        "impact": impact,
        "recommendation": recommendation,
        "details": details,
        "links": links,
        "cwe": cwe,
        "cvss": cvss,
    }
    return _post_json(path, _compact(data))


# --------------------------------------------------------------------------- #
# Configuration connectors - Scope Rules
# --------------------------------------------------------------------------- #
@mcp.tool()
def add_include_only_configuration(art_id: int, name: str, value: str, asset_ids: str) -> dict:
    """
    This endpoint creates an "include-only" scope configuration for assets in an Agentic Red Team (ART) project (restricts scanning to the given scope).

    Args:
        art_id (int): The id of the Agentic Red Team project.
        name (str): A descriptive name for the configuration.
        value (str): The include-only scope payload (e.g. paths/hosts to restrict scanning to).
        asset_ids (str): Comma-separated list of asset ids the configuration applies to, e.g. "1,2,3".

    Returns:
        dict
    """
    path = "AddIncludeOnlyConfiguration"
    data = {
        "art_id": art_id,
        "name": name,
        "value": value,
        "asset_ids": asset_ids,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def edit_include_only_configuration(art_id: int, conf_id: int, connector_id: int, name: str, value: str,
                                    asset_ids: str) -> dict:
    """
    This endpoint edits an "include-only" scope configuration in an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        conf_id (int): The id of the configuration to edit; retrieve valid ids via the `GetConfigurations` endpoint.
        connector_id (int): The id of the backing connector row.
        name (str): A descriptive name for the configuration.
        value (str): The include-only scope payload.
        asset_ids (str): Comma-separated list of asset ids the configuration applies to, e.g. "1,2,3".

    Returns:
        dict
    """
    path = "EditIncludeOnlyConfiguration"
    data = {
        "art_id": art_id,
        "conf_id": conf_id,
        "connector_id": connector_id,
        "name": name,
        "value": value,
        "asset_ids": asset_ids,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def add_art_exclude(art_id: int, exclude: str) -> dict:
    """
    This endpoint sets the project-wide exclude rules of an Agentic Red Team (ART) project (paths/hosts excluded from scanning).

    Args:
        art_id (int): The id of the Agentic Red Team project.
        exclude (str): The exclude payload (e.g. a JSON array of patterns to exclude).

    Returns:
        dict
    """
    path = "AddArtExclude"
    data = {
        "art_id": art_id,
        "exclude": exclude,
    }
    return _post_json(path, _compact(data))


# --------------------------------------------------------------------------- #
# Configuration connectors - Hosts File
# --------------------------------------------------------------------------- #
@mcp.tool()
def set_art_hosts_file(art_id: int, hosts: list) -> dict:
    """
    This endpoint creates or updates the hosts-file mappings of an Agentic Red Team (ART) project.


    Args:
        art_id (int): The id of the Agentic Red Team project.
        hosts (list): The COMPLETE list of host mappings as a native JSON array.

    Returns:
        dict
    """
    path = "SetArtHostsFile"
    data = {
        "art_id": art_id,
        "hosts": hosts,
    }
    return _post_json(path, _compact(data))




# --------------------------------------------------------------------------- #
# Configuration connectors - Attach Files
# --------------------------------------------------------------------------- #
@mcp.tool()
def add_art_group_files_configuration(art_id: int, conf_type: str, name: str, file_ids: str, asset_ids: str) -> dict:
    """
    This endpoint creates an attach-files (group files) configuration for assets in an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        conf_type (str): The attach-files configuration type.
        name (str): A descriptive name for the configuration.
        file_ids (str): Comma-separated list of uploaded file ids to attach, e.g. "1,2"; retrieve ids via `upload_file` / `get_files`.
        asset_ids (str): Comma-separated list of asset ids the configuration applies to, e.g. "1,2,3".

    Returns:
        dict
    """
    path = "AddArtGroupFilesConfiguration"
    data = {
        "art_id": art_id,
        "conf_type": conf_type,
        "name": name,
        "file_ids": file_ids,
        "asset_ids": asset_ids,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def edit_art_group_files_configuration(art_id: int, conf_id: int, connector_id: int, conf_type: str, name: str,
                                       file_ids: str, asset_ids: str) -> dict:
    """
    This endpoint edits an attach-files (group files) configuration in an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        conf_id (int): The id of the configuration to edit; retrieve valid ids via the `GetConfigurations` endpoint.
        connector_id (int): The id of the backing connector row.
        conf_type (str): The attach-files configuration type.
        name (str): A descriptive name for the configuration.
        file_ids (str): Comma-separated list of uploaded file ids to attach, e.g. "1,2".
        asset_ids (str): Comma-separated list of asset ids the configuration applies to, e.g. "1,2,3".

    Returns:
        dict
    """
    path = "EditArtGroupFilesConfiguration"
    data = {
        "art_id": art_id,
        "conf_id": conf_id,
        "connector_id": connector_id,
        "conf_type": conf_type,
        "name": name,
        "file_ids": file_ids,
        "asset_ids": asset_ids,
    }
    return _post_json(path, _compact(data))


# --------------------------------------------------------------------------- #
# Configuration connectors - Certificates (mTLS)
# --------------------------------------------------------------------------- #
@mcp.tool()
def add_certificates_configuration(art_id: int, value: str, name: str, asset_ids: str) -> dict:
    """
    This endpoint creates a client-certificate (mTLS) configuration for assets in an Agentic Red Team (ART) project.

    Security note: prefer uploading certificate material via `upload_file` (category "crt") and referencing it,
    rather than inlining secrets here. Do not paste real PFX passwords in shared/logged contexts.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        value (str): JSON payload describing the certificate(s) (e.g. PFX/PEM references); pass "[]" when there is none.
        name (str): A descriptive name for the configuration.
        asset_ids (str): Comma-separated list of asset ids the configuration applies to, e.g. "1,2,3".

    Returns:
        dict
    """
    path = "AddCertificatesConfiguration"
    data = {
        "art_id": art_id,
        "value": value,
        "name": name,
        "asset_ids": asset_ids,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def edit_certificates_configuration(art_id: int, conf_id: int, connector_id: int, value: str, name: str,
                                    asset_ids: str) -> dict:
    """
    This endpoint edits a client-certificate (mTLS) configuration in an Agentic Red Team (ART) project.

    Security note: prefer uploading certificate material via `upload_file` (category "crt") and referencing it.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        conf_id (int): The id of the configuration to edit; retrieve valid ids via the `GetConfigurations` endpoint.
        connector_id (int): The id of the backing connector row.
        value (str): JSON payload describing the certificate(s); pass "[]" when there is none.
        name (str): A descriptive name for the configuration.
        asset_ids (str): Comma-separated list of asset ids the configuration applies to, e.g. "1,2,3".

    Returns:
        dict
    """
    path = "EditCertificatesConfiguration"
    data = {
        "art_id": art_id,
        "conf_id": conf_id,
        "connector_id": connector_id,
        "value": value,
        "name": name,
        "asset_ids": asset_ids,
    }
    return _post_json(path, _compact(data))


# --------------------------------------------------------------------------- #
# Configuration connectors - Time Window
# --------------------------------------------------------------------------- #
@mcp.tool()
def add_time_window_configuration(art_id: int, start_day: str, end_day: str, start_hour: str, end_hour: str,
                                  name: str, asset_ids: str) -> dict:
    """
    This endpoint creates a scan time-window configuration for assets in an Agentic Red Team (ART) project (scanning only runs inside the window).

    Args:
        art_id (int): The id of the Agentic Red Team project.
        start_day (str): The first allowed day of the window (e.g. "Sunday" or "0").
        end_day (str): The last allowed day of the window (e.g. "Thursday" or "4").
        start_hour (str): The start hour of the window (e.g. "08:00").
        end_hour (str): The end hour of the window (e.g. "18:00").
        name (str): A descriptive name for the configuration.
        asset_ids (str): Comma-separated list of asset ids the configuration applies to, e.g. "1,2,3".

    Returns:
        dict
    """
    path = "AddTimeWindowConfiguration"
    data = {
        "art_id": art_id,
        "start_day": start_day,
        "end_day": end_day,
        "start_hour": start_hour,
        "end_hour": end_hour,
        "name": name,
        "asset_ids": asset_ids,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def edit_time_window_configuration(art_id: int, conf_id: int, connector_id: int, start_day: str, end_day: str,
                                   start_hour: str, end_hour: str, name: str, asset_ids: str) -> dict:
    """
    This endpoint edits a scan time-window configuration in an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        conf_id (int): The id of the configuration to edit; retrieve valid ids via the `GetConfigurations` endpoint.
        connector_id (int): The id of the backing connector row.
        start_day (str): The first allowed day of the window.
        end_day (str): The last allowed day of the window.
        start_hour (str): The start hour of the window (e.g. "08:00").
        end_hour (str): The end hour of the window (e.g. "18:00").
        name (str): A descriptive name for the configuration.
        asset_ids (str): Comma-separated list of asset ids the configuration applies to, e.g. "1,2,3".

    Returns:
        dict
    """
    path = "EditTimeWindowConfiguration"
    data = {
        "art_id": art_id,
        "conf_id": conf_id,
        "connector_id": connector_id,
        "start_day": start_day,
        "end_day": end_day,
        "start_hour": start_hour,
        "end_hour": end_hour,
        "name": name,
        "asset_ids": asset_ids,
    }
    return _post_json(path, _compact(data))


# --------------------------------------------------------------------------- #
# Configuration connectors - Agent Instructions & Recommendations
# --------------------------------------------------------------------------- #
@mcp.tool()
def add_agent_instructions(art_id: int, agent_instructions: str) -> dict:
    """
    This endpoint saves the custom agent instructions of an Agentic Red Team (ART) project (the read side is `get_agent_instructions`).

    Args:
        art_id (int): The id of the Agentic Red Team project.
        agent_instructions (str): The free-text instructions that steer the agent for this project.

    Returns:
        dict
    """
    path = "AddAgentInstructions"
    data = {
        "art_id": art_id,
        "agent_instructions": agent_instructions,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def get_configuration_recommendations(art_id: int) -> dict:
    """
    This endpoint returns configuration recommendations for an Agentic Red Team (ART) project (suggests missing configuration types).

    Args:
        art_id (int): The id of the Agentic Red Team project.

    Returns:
        dict
    """
    path = "GetConfigurationRecommendations"
    data = {
        "art_id": art_id,
    }
    return _post_json(path, _compact(data))


# --------------------------------------------------------------------------- #
# ART Vulnerabilities
# --------------------------------------------------------------------------- #
@mcp.tool()
def delete_art_vulnerability(art_id: int, vuln_id: int) -> dict:
    """
    This endpoint deletes a single vulnerability from an Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        vuln_id (int): The id of the vulnerability to delete; retrieve valid ids via the `GetArtVulnerabilities` endpoint.

    Returns:
        dict
    """
    path = "DeleteArtVulnerability"
    data = {
        "art_id": art_id,
        "vuln_id": vuln_id,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def delete_art_vulnerabilities(art_id: int, vuln_name: str | None = None, severity: str | None = None) -> dict:
    """
    This endpoint bulk-deletes vulnerabilities of an Agentic Red Team (ART) project by name and/or severity.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        vuln_name (str, optional): Delete all vulnerabilities with this name; defaults to "".
        severity (str, optional): Delete all vulnerabilities with this severity (e.g. "High", "Medium", "Low", "Informative"); defaults to "".

    Returns:
        dict
    """
    path = "DeleteArtVulnerabilities"
    data = {
        "art_id": art_id,
        "vuln_name": vuln_name,
        "severity": severity,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def fix_art_vulnerability(art_id: int, vuln_id: int, isfixed: bool) -> dict:
    """
    This endpoint marks a single Agentic Red Team (ART) vulnerability as fixed or not fixed.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        vuln_id (int): The id of the vulnerability; retrieve valid ids via the `GetArtVulnerabilities` endpoint.
        isfixed (bool): Set to True to mark the vulnerability as fixed, False to mark it as not fixed.

    Returns:
        dict
    """
    path = "FixArtVulnerability"
    data = {
        "art_id": art_id,
        "vuln_id": vuln_id,
        "isfixed": isfixed,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def fix_art_vulnerabilities(art_id: int, vuln_ids: str, isfixed: bool) -> dict:
    """
    This endpoint marks multiple Agentic Red Team (ART) vulnerabilities as fixed or not fixed.

    Args:
        art_id (int): The id of the Agentic Red Team project.
        vuln_ids (str): Comma-separated list of vulnerability ids, e.g. "12,13,14"; retrieve valid ids via the `GetArtVulnerabilities` endpoint.
        isfixed (bool): Set to True to mark the vulnerabilities as fixed, False to mark them as not fixed.

    Returns:
        dict
    """
    path = "FixArtVulnerabilities"
    data = {
        "art_id": art_id,
        "vuln_ids": vuln_ids,
        "isfixed": isfixed,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def export_art_vulnerabilities(vuln_ids: str) -> dict:
    """
    This endpoint exports the selected Agentic Red Team (ART) vulnerabilities as an Excel (.xlsx) file.

    Args:
        vuln_ids (str): Comma-separated list of vulnerability ids to export, e.g. "12,13,14"; retrieve valid ids via the `GetArtVulnerabilities` endpoint.

    Returns:
        dict
        - On success: {"Error": 0, "Function", "filename", "mime_type",
          "encoding": "base64", "size", "content_base64"}. Decode
          `content_base64` (Base64) to recover the .xlsx file bytes.
        - On failure: {"Error": 1, "Function", "Data"}.
    """
    path = "ExportArtVulnerabilities"
    data = {
        "vuln_ids": vuln_ids,
    }
    return _post_binary(path, _compact(data), filename="art_vulnerabilities.xlsx")


# --------------------------------------------------------------------------- #
# ART User Preferences
# --------------------------------------------------------------------------- #
@mcp.tool()
def update_user_main_art_id(art_id: int) -> dict:
    """
    This endpoint sets the calling user's default/landing Agentic Red Team (ART) project.

    Args:
        art_id (int): The id of the Agentic Red Team project to set as the user's main project.

    Returns:
        dict
    """
    path = "UpdateUserMainArtId"
    data = {
        "art_id": art_id,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def get_in_progress_improvement_art() -> dict:
    """
    This endpoint returns a per-user summary of Agentic Red Team (ART) projects with in-progress improvement activity (used for status badges / polling).

    Returns:
        dict
    """
    path = "GetInProgressImprovementArt"
    return _post_json(path, {})


# --------------------------------------------------------------------------- #
# Shared Resources - Files
# --------------------------------------------------------------------------- #
@mcp.tool()
def upload_file(name: str, fileExtension: str, file: str, category: str, description: str | None = None) -> dict:
    """
    This endpoint uploads a file to the tenant storage for use by ART configurations (attach-files, certificates, AI-action files, API schemas).

    Args:
        name (str): Descriptive name for the uploaded file.
        fileExtension (str): File extension without the dot, e.g. "json", "pfx", "docx".
        file (str): Base64-encoded content of the file.
        category (str): File category; one of "api_schema", "img", "crt", "custom_template", "idor_params".
        description (str, optional): Brief description of the file's purpose; defaults to "".

    Returns:
        dict
        - The returned file id can be passed as `file_ids` to attach-files / AI-action configurations.
    """
    # `file` arrives Base64-encoded (that is the tool's documented input).
    # Validate and DECODE it to the raw bytes, then send it as a real
    # multipart file part: the backend reads the upload from
    # `request.files['file']`, so a Base64 string in a JSON body never reaches
    # it (it lands in `request.form`) and the upload fails with "Missing file".
    if not isinstance(file, str) or not file.strip():
        return _api_error("UploadFile", "`file` must be a non-empty Base64-encoded string")
    try:
        # Tolerate whitespace/newlines in the supplied Base64 while still
        # rejecting genuinely malformed content.
        blob = base64.b64decode("".join(file.split()), validate=True)
    except (binascii.Error, ValueError):
        return _api_error("UploadFile", "`file` must be valid Base64-encoded content")

    file_name = f"{name}.{fileExtension}" if (name and fileExtension) else (name or "upload")
    fields = {
        "name": name,
        "fileExtension": fileExtension,
        "category": category,
        "description": description,
    }
    return _post_file("UploadFile", fields, file_name, blob)


@mcp.tool()
def get_files(category: str | None = None, onlyName: bool | None = None) -> dict:
    """
    This endpoint lists the files stored in the tenant storage, optionally filtered by category.

    Args:
        category (str, optional): Filter by file category, e.g. "crt", "api_schema"; defaults to "".
        onlyName (bool, optional): Set to True to return only file names; defaults to False.

    Returns:
        dict
    """
    path = "GetFiles"
    data = {
        "category": category,
        "onlyName": onlyName,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def delete_file(name: str) -> dict:
    """
    This endpoint deletes a file from the tenant storage.

    Args:
        name (str): System-registered identifier of the file to delete; retrieve valid values via the `GetFiles` endpoint.

    Returns:
        dict
    """
    path = "DeleteFile"
    data = {
        "name": name,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def is_file_configure(file_id: int) -> dict:
    """
    This endpoint checks whether a stored file is referenced by any configuration (used as a delete guard).

    Args:
        file_id (int): The id of the file to check; retrieve valid ids via the `GetFiles` endpoint.

    Returns:
        dict
    """
    path = "IsFileConfigure"
    data = {
        "file_id": file_id,
    }
    return _post_json(path, _compact(data))


# --------------------------------------------------------------------------- #
# Shared Resources - Brokers (read-only)
# --------------------------------------------------------------------------- #
@mcp.tool()
def get_brokers() -> dict:
    """
    This endpoint lists the configured brokers (OpenZiti) available to the tenant. Internal-asset scans and `run_ai_action` for internal targets require a broker.

    Returns:
        dict
    """
    path = "GetBrokers"
    return _post_json(path, {})


# --------------------------------------------------------------------------- #
# Shared Resources - Fixed IP
# --------------------------------------------------------------------------- #
@mcp.tool()
def get_all_fixed_ip() -> dict:
    """
    This endpoint returns the fixed (static source) IPs allocated to the tenant. Each row carries `id` and `fixed_ip_value`; the `id` is what `AddConfiguration` takes as `connector_id` for conf_type='fixed_ip'.

    Returns:
        dict
    """
    path = "GetAllFixedIP"
    return _post_json(path, {})


# --------------------------------------------------------------------------- #
# Shared Resources - Attack Profiles
# --------------------------------------------------------------------------- #
@mcp.tool()
def new_attack_profile(profile_name: str, profiles: str) -> dict:
    """
    This endpoint creates a new attack profile (reusable set of attack engines) usable by ART and classic scans.

    Args:
        profile_name (str): Descriptive name for the new attack profile.
        profiles (str): Comma-separated list of attack-option ids to include, e.g. "7,8,9,10"; retrieve valid ids via the `GetAttackOptions` endpoint.

    Returns:
        dict
    """
    path = "NewAttackProfile"
    data = {
        "profile_name": profile_name,
        "profiles": profiles,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def edit_attack_profile(profile_id: int, profile_name: str | None = None, profiles: str | None = None) -> dict:
    """
    This endpoint edits an existing attack profile.

    Args:
        profile_id (int): The id of the attack profile to edit; retrieve valid ids via the `GetAllAttackProfile` endpoint.
        profile_name (str, optional): New name for the attack profile; defaults to "".
        profiles (str, optional): Comma-separated list of attack-option ids, e.g. "7,8,9,10"; defaults to "".

    Returns:
        dict
    """
    path = "EditAttackProfile"
    data = {
        "profile_id": profile_id,
        "profile_name": profile_name,
        "profiles": profiles,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def duplicate_attack_profile(profile_id: int) -> dict:
    """
    This endpoint duplicates an existing attack profile.

    Args:
        profile_id (int): The id of the attack profile to duplicate; retrieve valid ids via the `GetAllAttackProfile` endpoint.

    Returns:
        dict
    """
    path = "DuplicateAttackProfile"
    data = {
        "profile_id": profile_id,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def delete_attack_profile(profile_name: str) -> dict:
    """
    This endpoint deletes an existing attack profile.

    Args:
        profile_name (str): The name of the attack profile to delete; retrieve valid names via the `GetAllAttackProfile` endpoint.

    Returns:
        dict
    """
    path = "DeleteAttackProfile"
    data = {
        "profile_name": profile_name,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def get_attack_profile(profile_id: int) -> dict:
    """
    This endpoint retrieves a single attack profile.

    Args:
        profile_id (int): The id of the attack profile to retrieve; retrieve valid ids via the `GetAllAttackProfile` endpoint.

    Returns:
        dict
    """
    path = "GetAttackProfile"
    data = {
        "profile_id": profile_id,
    }
    return _post_json(path, _compact(data))


@mcp.tool()
def get_all_attack_profile() -> dict:
    """
    This endpoint retrieves all attack profiles defined for the tenant.

    Returns:
        dict
    """
    path = "GetAllAttackProfile"
    return _post_json(path, {})


@mcp.tool()
def get_attack_options() -> dict:
    """
    This endpoint retrieves the catalog of attack options (engines) that can be combined into an attack profile.

    Returns:
        dict
    """
    path = "GetAttackOptions"
    return _post_json(path, {})


@mcp.tool()
def is_attack_profile_configure() -> dict:
    """
    This endpoint checks whether any attack profile is configured for the tenant (used as a config guard).

    Returns:
        dict
    """
    path = "IsAttackProfileConfigure"
    return _post_json(path, {})
