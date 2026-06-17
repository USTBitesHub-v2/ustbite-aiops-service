from pydantic import BaseModel
from typing import Any


class AnalyzeRequest(BaseModel):
    query: str
    namespaces: list[str] = []
    time_range_minutes: int = 30


class ToolCallInfo(BaseModel):
    tool: str
    args: dict[str, Any]
    result: Any


class RemediationAction(BaseModel):
    action_type: str  # "restart_deployment" | "scale_deployment" | "delete_pod" | "create_github_pr"
    namespace: str
    target: str
    # For create_github_pr: `target` is the file path (e.g. "charts/payment-service/values.prod.yaml")
    # relative to the ustbite-helm-charts repo root, and `params` carries:
    #   key_path: dotted path to the value to change, e.g. "resources.limits.memory"
    #   new_value: the replacement value
    #   pr_title / pr_description: optional override text for the PR
    params: dict[str, Any] = {}
    description: str
    requires_approval: bool = True


class AnalyzeResponse(BaseModel):
    root_cause: str
    affected_services: list[str]
    severity: str  # "critical" | "high" | "medium" | "low"
    recommendations: list[str]
    proposed_actions: list[RemediationAction]
    tool_calls_made: list[ToolCallInfo]


class ExecuteActionRequest(BaseModel):
    action: RemediationAction


class ActionResult(BaseModel):
    success: bool
    message: str
    output: str = ""
