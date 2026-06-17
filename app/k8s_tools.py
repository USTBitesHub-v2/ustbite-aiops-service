import asyncio
import logging
import re
from datetime import datetime, timezone

from kubernetes import client, config
from kubernetes.client.rest import ApiException

logger = logging.getLogger(__name__)

# Safe commands that may be executed inside a pod via exec
_EXEC_ALLOWLIST = [
    r"^(ls|ps|df|free|env|hostname|date|uptime)(\s.*)?$",
    r"^cat\s+/proc/(cpuinfo|meminfo|version|mounts)$",
    r"^netstat\s+(-.+)?$",
    r"^curl\s+http://localhost(:\d+)?(/\S*)?$",
]

MANAGED_NAMESPACES = {
    "ustbite-backend",
    "ustbite-frontend",
    "ustbite-ops",
    "ingress-nginx",
    "argocd",
}


def _init_k8s() -> tuple[client.CoreV1Api, client.AppsV1Api]:
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.CoreV1Api(), client.AppsV1Api()


_v1, _apps_v1 = _init_k8s()


def _age(ts) -> str:
    if not ts:
        return "unknown"
    delta = datetime.now(timezone.utc) - ts
    s = int(delta.total_seconds())
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h"
    return f"{s // 86400}d"


def _ns_ok(namespace: str) -> bool:
    if namespace == "all":
        return True
    if namespace not in MANAGED_NAMESPACES:
        logger.warning("Rejected access to unmanaged namespace: %s", namespace)
        return False
    return True


# ── Read-only tools (safe for agent to call directly) ────────────────────────

async def list_pods(namespace: str = "all") -> list[dict]:
    if not _ns_ok(namespace):
        return [{"error": f"Namespace '{namespace}' is not in the managed list"}]
    try:
        items = (
            (await asyncio.to_thread(_v1.list_pod_for_all_namespaces)).items
            if namespace == "all"
            else (await asyncio.to_thread(_v1.list_namespaced_pod, namespace=namespace)).items
        )
        result = []
        for pod in items:
            cs_list = pod.status.container_statuses or []
            ready = all(cs.ready for cs in cs_list) if cs_list else False
            restarts = sum(cs.restart_count for cs in cs_list)
            result.append({
                "name": pod.metadata.name,
                "namespace": pod.metadata.namespace,
                "phase": pod.status.phase or "Unknown",
                "ready": ready,
                "restarts": restarts,
                "age": _age(pod.metadata.creation_timestamp),
                "node": pod.spec.node_name or "unscheduled",
            })
        return result
    except ApiException as exc:
        return [{"error": str(exc)}]


async def get_pod_logs(namespace: str, pod_name: str, tail_lines: int = 150) -> str:
    if not _ns_ok(namespace):
        return f"Error: namespace '{namespace}' not managed"
    try:
        logs = await asyncio.to_thread(
            _v1.read_namespaced_pod_log,
            name=pod_name,
            namespace=namespace,
            tail_lines=tail_lines,
            timestamps=True,
        )
        return logs or "(no logs)"
    except ApiException as exc:
        return f"Error fetching logs: {exc}"


async def get_pod_events(namespace: str, pod_name: str) -> list[dict]:
    if not _ns_ok(namespace):
        return [{"error": f"Namespace '{namespace}' not managed"}]
    try:
        fs = f"involvedObject.name={pod_name},involvedObject.namespace={namespace}"
        resp = await asyncio.to_thread(_v1.list_namespaced_event, namespace=namespace, field_selector=fs)
        return [
            {
                "type": e.type,
                "reason": e.reason,
                "message": e.message,
                "count": e.count,
                "last_seen": str(e.last_timestamp),
            }
            for e in resp.items
        ]
    except ApiException as exc:
        return [{"error": str(exc)}]


async def get_deployment_status(namespace: str, deployment_name: str) -> dict:
    if not _ns_ok(namespace):
        return {"error": f"Namespace '{namespace}' not managed"}
    try:
        dep = await asyncio.to_thread(
            _apps_v1.read_namespaced_deployment, name=deployment_name, namespace=namespace
        )
        st = dep.status
        return {
            "name": dep.metadata.name,
            "namespace": namespace,
            "desired": dep.spec.replicas,
            "ready": st.ready_replicas or 0,
            "available": st.available_replicas or 0,
            "updated": st.updated_replicas or 0,
            "conditions": [
                {"type": c.type, "status": c.status, "message": c.message}
                for c in (st.conditions or [])
            ],
        }
    except ApiException as exc:
        return {"error": str(exc)}


async def search_logs_for_errors(namespace: str, tail_lines: int = 300) -> dict:
    """Scan all pods in a namespace and return pods with ERROR/CRITICAL/Traceback lines."""
    pods = await list_pods(namespace)
    pattern = re.compile(
        r"(ERROR|CRITICAL|EXCEPTION|Traceback|panic:|OOMKilled|CrashLoopBackOff|failed)", re.I
    )
    results: dict[str, list[str]] = {}
    for pod in pods[:12]:  # cap to avoid timeouts
        if "error" in pod:
            continue
        logs = await get_pod_logs(namespace, pod["name"], tail_lines=tail_lines)
        errors = [line for line in logs.splitlines() if pattern.search(line)]
        if errors:
            results[pod["name"]] = errors[-25:]
    return results or {"status": "No error patterns found in recent logs"}


async def get_cluster_overview() -> dict:
    """High-level health across all managed namespaces."""
    all_pods = await list_pods("all")
    total = len(all_pods)
    unhealthy = [p for p in all_pods if not p.get("ready") or p.get("restarts", 0) > 5]
    by_ns: dict[str, dict] = {}
    for p in all_pods:
        ns = p.get("namespace", "?")
        if ns not in by_ns:
            by_ns[ns] = {"total": 0, "unhealthy": 0}
        by_ns[ns]["total"] += 1
        if not p.get("ready") or p.get("restarts", 0) > 5:
            by_ns[ns]["unhealthy"] += 1
    return {
        "total_pods": total,
        "unhealthy_pods": len(unhealthy),
        "unhealthy_details": unhealthy[:10],
        "by_namespace": by_ns,
    }


# ── Write operations (called only after admin approval) ──────────────────────

async def restart_deployment(namespace: str, deployment_name: str) -> dict:
    if not _ns_ok(namespace):
        return {"error": f"Namespace '{namespace}' not managed"}
    try:
        patch = {
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            "kubectl.kubernetes.io/restartedAt": datetime.now(timezone.utc).isoformat()
                        }
                    }
                }
            }
        }
        await asyncio.to_thread(
            _apps_v1.patch_namespaced_deployment,
            name=deployment_name,
            namespace=namespace,
            body=patch,
        )
        return {"success": True, "message": f"Restart triggered for deployment '{deployment_name}'"}
    except ApiException as exc:
        return {"success": False, "error": str(exc)}


async def scale_deployment(namespace: str, deployment_name: str, replicas: int) -> dict:
    if not _ns_ok(namespace):
        return {"error": f"Namespace '{namespace}' not managed"}
    if replicas < 0 or replicas > 10:
        return {"error": "replicas must be between 0 and 10"}
    try:
        patch = {"spec": {"replicas": replicas}}
        await asyncio.to_thread(
            _apps_v1.patch_namespaced_deployment,
            name=deployment_name,
            namespace=namespace,
            body=patch,
        )
        return {"success": True, "message": f"Scaled '{deployment_name}' to {replicas} replicas"}
    except ApiException as exc:
        return {"success": False, "error": str(exc)}


async def delete_pod(namespace: str, pod_name: str) -> dict:
    if not _ns_ok(namespace):
        return {"error": f"Namespace '{namespace}' not managed"}
    try:
        await asyncio.to_thread(_v1.delete_namespaced_pod, name=pod_name, namespace=namespace)
        return {"success": True, "message": f"Pod '{pod_name}' deleted — Deployment will reschedule it"}
    except ApiException as exc:
        return {"success": False, "error": str(exc)}


async def exec_in_pod(namespace: str, pod_name: str, command: list[str]) -> str:
    """Execute a whitelisted diagnostic command in a pod."""
    if not _ns_ok(namespace):
        return f"Error: namespace '{namespace}' not managed"
    cmd_str = " ".join(command)
    if not any(re.match(p, cmd_str) for p in _EXEC_ALLOWLIST):
        return f"Command '{cmd_str}' is not in the diagnostic allowlist."
    try:
        from kubernetes.stream import stream
        resp = await asyncio.to_thread(
            stream,
            _v1.connect_get_namespaced_pod_exec,
            pod_name,
            namespace,
            command=command,
            stderr=True,
            stdin=False,
            stdout=True,
            tty=False,
        )
        return resp or "(no output)"
    except ApiException as exc:
        return f"Exec error: {exc}"
