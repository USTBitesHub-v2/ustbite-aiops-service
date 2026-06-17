from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    AWS_REGION: str = "us-east-1"
    BEDROCK_MODEL_ID: str = "amazon.nova-lite-v1:0"
    CLUSTER_NAME: str = "ustbite-prod"
    SERVICE_PORT: str = "8011"
    LOG_LEVEL: str = "INFO"
    ADMIN_API_KEY: str = ""

    GITHUB_TOKEN: str = ""
    GITHUB_OWNER: str = ""
    GITHUB_REPO: str = "ustbite-helm-charts"

    MANAGED_NAMESPACES: list[str] = [
        "ustbite-backend",
        "ustbite-frontend",
        "ustbite-ops",
        "ingress-nginx",
        "argocd",
    ]

    class Config:
        env_file = ".env"


settings = Settings()
