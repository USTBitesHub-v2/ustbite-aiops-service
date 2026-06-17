import base64
import logging
import re
import time
from io import StringIO
from typing import Any

import httpx
from ruamel.yaml import YAML

from app.config import settings

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"

# Hard allow-list, enforced in code (not just prompted) — the agent can never be tricked
# into patching arbitrary files or keys, e.g. secrets, RBAC, or anything outside Helm values.
_ALLOWED_FILE_PATTERN = re.compile(r"^charts/[\w-]+/values\.prod\.yaml$")
_ALLOWED_KEY_PATHS = {
    "replicaCount",
    "resources.limits.cpu",
    "resources.limits.memory",
    "resources.requests.cpu",
    "resources.requests.memory",
    "autoscaling.enabled",
    "autoscaling.minReplicas",
    "autoscaling.maxReplicas",
    "autoscaling.targetCPUUtilizationPercentage",
}
_INT_KEYS = {"replicaCount", "autoscaling.minReplicas", "autoscaling.maxReplicas", "autoscaling.targetCPUUtilizationPercentage"}
_BOOL_KEYS = {"autoscaling.enabled"}


class RemediationPRError(Exception):
    pass


def _validate(file_path: str, key_path: str) -> None:
    if not _ALLOWED_FILE_PATTERN.match(file_path):
        raise RemediationPRError(
            f"File '{file_path}' is not allowed — only charts/*/values.prod.yaml may be modified."
        )
    if key_path not in _ALLOWED_KEY_PATHS:
        raise RemediationPRError(
            f"Key '{key_path}' is not allowed. Allowed keys: {sorted(_ALLOWED_KEY_PATHS)}"
        )


def _coerce_value(key_path: str, new_value: Any) -> Any:
    if key_path in _INT_KEYS:
        return int(new_value)
    if key_path in _BOOL_KEYS:
        if isinstance(new_value, bool):
            return new_value
        return str(new_value).strip().lower() in {"true", "1", "yes"}
    return str(new_value)


def _apply_key_path(data: dict, key_path: str, new_value: Any) -> None:
    parts = key_path.split(".")
    node = data
    for part in parts[:-1]:
        node = node[part]
    node[parts[-1]] = new_value


def _yaml() -> YAML:
    y = YAML()
    y.preserve_quotes = True
    y.indent(mapping=2, sequence=2, offset=0)
    return y


async def _gh_request(client: httpx.AsyncClient, method: str, path: str, **kwargs) -> httpx.Response:
    if not settings.GITHUB_TOKEN:
        raise RemediationPRError("GITHUB_TOKEN is not configured for this service.")

    headers = {
        "Authorization": f"Bearer {settings.GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    response = await client.request(method, f"{GITHUB_API}{path}", headers=headers, **kwargs)
    if response.status_code >= 400:
        raise RemediationPRError(f"GitHub API {method} {path} failed ({response.status_code}): {response.text}")
    return response


async def create_remediation_pr(
    file_path: str,
    key_path: str,
    new_value: Any,
    description: str,
    pr_title: str | None = None,
    pr_description: str | None = None,
    owner: str | None = None,
    repo: str | None = None,
) -> dict:
    """Opens a PR that changes one allow-listed key in one allow-listed values.prod.yaml file."""
    _validate(file_path, key_path)
    owner = owner or settings.GITHUB_OWNER
    repo = repo or settings.GITHUB_REPO
    if not owner:
        raise RemediationPRError("GITHUB_OWNER is not configured for this service.")

    coerced_value = _coerce_value(key_path, new_value)
    branch_name = f"aiops/{file_path.split('/')[1]}-{key_path.replace('.', '-')}-{int(time.time())}"

    async with httpx.AsyncClient(timeout=15.0) as client:
        repo_info = (await _gh_request(client, "GET", f"/repos/{owner}/{repo}")).json()
        default_branch = repo_info["default_branch"]

        ref_info = (
            await _gh_request(client, "GET", f"/repos/{owner}/{repo}/git/ref/heads/{default_branch}")
        ).json()
        base_sha = ref_info["object"]["sha"]

        await _gh_request(
            client,
            "POST",
            f"/repos/{owner}/{repo}/git/refs",
            json={"ref": f"refs/heads/{branch_name}", "sha": base_sha},
        )

        file_info = (
            await _gh_request(
                client, "GET", f"/repos/{owner}/{repo}/contents/{file_path}", params={"ref": default_branch}
            )
        ).json()
        raw_content = base64.b64decode(file_info["content"]).decode("utf-8")

        yaml = _yaml()
        data = yaml.load(StringIO(raw_content))
        _apply_key_path(data, key_path, coerced_value)

        buf = StringIO()
        yaml.dump(data, buf)
        new_content = buf.getvalue()

        commit_message = pr_title or f"aiops: set {key_path}={coerced_value} in {file_path}"
        await _gh_request(
            client,
            "PUT",
            f"/repos/{owner}/{repo}/contents/{file_path}",
            json={
                "message": commit_message,
                "content": base64.b64encode(new_content.encode("utf-8")).decode("utf-8"),
                "sha": file_info["sha"],
                "branch": branch_name,
            },
        )

        pr_body = pr_description or (
            f"Automated remediation proposed by USTBites AI Ops.\n\n"
            f"**File:** `{file_path}`\n**Key:** `{key_path}`\n**New value:** `{coerced_value}`\n\n"
            f"**Reason:** {description}\n\n"
            f"_This PR was opened after admin approval in the AI Ops console — review the diff before merging._"
        )
        pr = (
            await _gh_request(
                client,
                "POST",
                f"/repos/{owner}/{repo}/pulls",
                json={
                    "title": commit_message,
                    "head": branch_name,
                    "base": default_branch,
                    "body": pr_body,
                },
            )
        ).json()

        return {"pr_url": pr["html_url"], "pr_number": pr["number"], "branch": branch_name}
