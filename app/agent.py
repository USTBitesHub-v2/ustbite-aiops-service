import asyncio
import json
import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from app.config import settings
from app.models import AnalyzeResponse, RemediationAction, ToolCallInfo
from app.k8s_tools import (
    list_pods,
    get_pod_logs,
    get_pod_events,
    get_deployment_status,
    search_logs_for_errors,
    get_cluster_overview,
)

logger = logging.getLogger(__name__)

MAX_ITERATIONS = 10
_RETRY_EXCEPTIONS = {"ThrottlingException", "ServiceUnavailableException", "ModelTimeoutException"}

# ── Tool definitions ──────────────────────────────────────────────────────────

_BEDROCK_TOOLS = [
    {
        "toolSpec": {
            "name": "get_cluster_overview",
            "description": "Get a high-level health summary of all pods across all managed namespaces. Use this first to understand the scope of the problem.",
            "inputSchema": {"json": {"type": "object", "properties": {}, "required": []}},
        }
    },
    {
        "toolSpec": {
            "name": "list_pods",
            "description": "List all pods in a namespace with their phase, readiness, restart count, and age.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "namespace": {
                            "type": "string",
                            "description": "Kubernetes namespace. Use 'all' for all namespaces.",
                        }
                    },
                    "required": ["namespace"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "get_pod_logs",
            "description": "Get recent logs from a specific pod. Focus on pods that are unhealthy or restarting.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "namespace": {"type": "string"},
                        "pod_name": {"type": "string", "description": "Full pod name"},
                        "tail_lines": {
                            "type": "integer",
                            "description": "Number of recent log lines to fetch (default 150)",
                        },
                    },
                    "required": ["namespace", "pod_name"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "get_pod_events",
            "description": "Get Kubernetes events for a specific pod. Useful for OOMKilled, ImagePullBackOff, CrashLoopBackOff diagnosis.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "namespace": {"type": "string"},
                        "pod_name": {"type": "string"},
                    },
                    "required": ["namespace", "pod_name"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "get_deployment_status",
            "description": "Get the rollout status of a Deployment (desired vs ready vs available replicas, conditions).",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "namespace": {"type": "string"},
                        "deployment_name": {"type": "string"},
                    },
                    "required": ["namespace", "deployment_name"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "search_logs_for_errors",
            "description": "Scan all pods in a namespace for ERROR, CRITICAL, Traceback, OOMKilled patterns. Use to quickly identify which pods have problems.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "namespace": {"type": "string"},
                        "tail_lines": {"type": "integer", "description": "Lines to scan per pod (default 300)"},
                    },
                    "required": ["namespace"],
                }
            },
        }
    },
]

_SYSTEM_PROMPT = """You are an expert AI Site Reliability Engineer for USTBites, a food delivery platform running on AWS EKS.

Managed namespaces:
- ustbite-backend: user-service, restaurant-service, order-service, payment-service, delivery-service, notification-service, cart-service, ai-agent-service
- ustbite-frontend: frontend (React SPA)
- ustbite-ops: aiops-service (this service)
- ingress-nginx: nginx ingress controller
- argocd: ArgoCD GitOps controller

Investigation protocol:
1. Start with get_cluster_overview to understand the scope (which namespaces/pods are unhealthy)
2. Use list_pods for the specific namespace to identify exact failing pods
3. Use get_pod_events for any pod with high restart count or non-Running phase
4. Use get_pod_logs for pods with events suggesting crashes or errors
5. Use search_logs_for_errors if the problem is unclear — scan the entire namespace
6. Use get_deployment_status to understand rollout state
7. Cross-reference across multiple services if the issue might be cascading

Output format (after your analysis is complete — use end_turn):
Provide your findings in this exact JSON structure embedded in your response:
{
  "root_cause": "One clear sentence describing the root cause",
  "affected_services": ["service-name-1", "service-name-2"],
  "severity": "critical|high|medium|low",
  "recommendations": ["Step 1 to fix", "Step 2 to fix"],
  "proposed_actions": [
    {
      "action_type": "restart_deployment|scale_deployment|delete_pod|create_github_pr",
      "namespace": "ustbite-backend",
      "target": "deployment-or-pod-name",
      "params": {},
      "description": "What this action does and why",
      "requires_approval": true
    }
  ]
}

Rules:
- Never guess — only use data from tool results
- Proposed actions ALWAYS have requires_approval: true
- For scale_deployment, include params: {"replicas": N}
- If you cannot determine root cause with confidence, say so explicitly
- Severity: critical=service down, high=degraded, medium=warnings, low=cosmetic

create_github_pr action (use for durable config fixes instead of live cluster mutations,
e.g. "this deployment needs a permanently higher memory limit" rather than a one-off OOMKill):
- namespace: not meaningful for this action type — set it to "github"
- target: the Helm values file to patch, relative to the ustbite-helm-charts repo root,
  e.g. "charts/payment-service/values.prod.yaml". Only charts/*/values.prod.yaml files are permitted.
- params: {"key_path": "resources.limits.memory", "new_value": "512Mi"} — key_path must be one of:
  replicaCount, resources.limits.cpu, resources.limits.memory, resources.requests.cpu,
  resources.requests.memory, autoscaling.enabled, autoscaling.minReplicas, autoscaling.maxReplicas,
  autoscaling.targetCPUUtilizationPercentage. Optionally also include "pr_title"/"pr_description".
- Only propose this action type for changes within that key allow-list — anything else
  (image tags, secrets, RBAC, arbitrary files) is rejected by the execution layer regardless."""


# ── Bedrock call with retry ───────────────────────────────────────────────────

async def _converse(bedrock_client: Any, **kwargs: Any) -> dict:
    for attempt in range(3):
        try:
            return await asyncio.to_thread(bedrock_client.converse, **kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in _RETRY_EXCEPTIONS and attempt < 2:
                wait = 2 ** attempt
                logger.warning("Bedrock %s — retrying in %ds", code, wait)
                await asyncio.sleep(wait)
            else:
                raise
    raise RuntimeError("Bedrock call failed after retries")


# ── Tool dispatcher ───────────────────────────────────────────────────────────

async def _dispatch(tool_name: str, args: dict) -> Any:
    if tool_name == "get_cluster_overview":
        return await get_cluster_overview()
    if tool_name == "list_pods":
        return await list_pods(args.get("namespace", "all"))
    if tool_name == "get_pod_logs":
        return await get_pod_logs(args["namespace"], args["pod_name"], args.get("tail_lines", 150))
    if tool_name == "get_pod_events":
        return await get_pod_events(args["namespace"], args["pod_name"])
    if tool_name == "get_deployment_status":
        return await get_deployment_status(args["namespace"], args["deployment_name"])
    if tool_name == "search_logs_for_errors":
        return await search_logs_for_errors(args["namespace"], args.get("tail_lines", 300))
    return {"error": f"Unknown tool: {tool_name}"}


# ── Parse agent output for structured response ────────────────────────────────

def _parse_response(text: str) -> dict:
    import re
    match = re.search(r"\{[\s\S]*\}", text)
    if not match:
        return {}
    try:
        return json.loads(match.group())
    except json.JSONDecodeError:
        return {}


# ── Main entry point ──────────────────────────────────────────────────────────

async def run_analysis(query: str, namespaces: list[str]) -> AnalyzeResponse:
    bedrock = boto3.client("bedrock-runtime", region_name=settings.AWS_REGION)
    tool_calls_made: list[ToolCallInfo] = []

    context = f"Problem reported: {query}"
    if namespaces:
        context += f"\nInvestigate these namespaces first: {', '.join(namespaces)}"

    messages: list[dict] = [{"role": "user", "content": [{"text": context}]}]

    for iteration in range(MAX_ITERATIONS):
        logger.info("AIOps iteration %d", iteration + 1)

        response = await _converse(
            bedrock,
            modelId=settings.BEDROCK_MODEL_ID,
            system=[{"text": _SYSTEM_PROMPT}],
            messages=messages,
            toolConfig={"tools": _BEDROCK_TOOLS},
        )

        output_message = response["output"]["message"]
        stop_reason = response["stopReason"]
        messages.append(output_message)

        if stop_reason == "end_turn":
            text = next(
                (b["text"] for b in output_message["content"] if "text" in b), ""
            )
            parsed = _parse_response(text)

            proposed = [
                RemediationAction(**a)
                for a in parsed.get("proposed_actions", [])
                if isinstance(a, dict)
            ]

            return AnalyzeResponse(
                root_cause=parsed.get("root_cause", text[:300] if text else "Analysis complete."),
                affected_services=parsed.get("affected_services", []),
                severity=parsed.get("severity", "medium"),
                recommendations=parsed.get("recommendations", []),
                proposed_actions=proposed,
                tool_calls_made=tool_calls_made,
            )

        if stop_reason != "tool_use":
            break

        tool_results: list[dict] = []
        for block in output_message["content"]:
            if "toolUse" not in block:
                continue
            tool_use = block["toolUse"]
            fn_name = tool_use["name"]
            fn_args = tool_use["input"]
            result = await _dispatch(fn_name, fn_args)
            tool_calls_made.append(ToolCallInfo(tool=fn_name, args=fn_args, result=result))
            tool_results.append({
                "toolResult": {"toolUseId": tool_use["toolUseId"], "content": [{"json": result}]}
            })

        messages.append({"role": "user", "content": tool_results})

    return AnalyzeResponse(
        root_cause="Analysis reached iteration limit without a conclusion.",
        affected_services=[],
        severity="medium",
        recommendations=["Try narrowing the query to a specific namespace or service."],
        proposed_actions=[],
        tool_calls_made=tool_calls_made,
    )
