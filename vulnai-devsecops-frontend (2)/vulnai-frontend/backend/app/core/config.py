from pydantic_settings import BaseSettings, SettingsConfigDict
from app.core.paths import APP_ROOT, SCAN_RESULTS_ROOT, WORDLIST_PATH

class Settings(BaseSettings):
    app_name: str = "VulnAI DevSecOps API"
    environment: str = "development"

    database_url: str = ""

    jwt_secret_key: str = "replace_this_with_a_long_random_secret_key"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 1440

    frontend_origins: str = "http://localhost:5173"

    scan_timeout_seconds: int = 15
    scan_job_timeout_seconds: int = 1800
    max_redirects: int = 5
    scanner_wsl_distribution: str = "kali-linux"
    nikto_docker_image: str = "sullo/nikto:latest"
    scanner_docker_command: str = "docker"

    allow_private_targets: bool = False
    lab_mode: bool = False

    gemini_api_key: str | None = None
    openai_api_key: str | None = None

    kali_script_path: str = str(APP_ROOT / "scripts" / "kali_scanner.sh")
    scan_output_dir: str = str(SCAN_RESULTS_ROOT)
    kali_wordlist: str = str(WORDLIST_PATH)
    kali_enabled: bool = True
    wappalyzer_path: str | None = None

    model_config = SettingsConfigDict(
        env_file=(APP_ROOT / ".env", APP_ROOT.parent / ".env"),
        case_sensitive=False,
        extra="ignore"
    )

settings = Settings()
