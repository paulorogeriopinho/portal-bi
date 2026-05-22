import requests
import os
import msal
from datetime import datetime, timedelta
from threading import Lock
from typing import Optional

TENANT_ID     = os.getenv("TENANT_ID")
CLIENT_ID     = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
AUTHORITY     = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPE         = ["https://analysis.windows.net/powerbi/api/.default"]
PBI_API       = "https://api.powerbi.com/v1.0/myorg"

# ── Cache de tokens ──────────────────────────────────────────────
# Lock para thread safety (Flask pode ter múltiplas threads)
_cache_lock = Lock()

# Cache do access token do Azure (compartilhado por todos os usuários)
_access_token_cache = {
    "token":      None,
    "expires_at": datetime.utcnow()
}

# Cache dos embed tokens do Power BI (por relatório + usuário + RLS)
# Estrutura: { cache_key: {"embed_token": ..., "embed_url": ..., "report_id": ..., "expires_at": ...} }
_embed_token_cache = {}

# Margem de segurança: renova o token 5 minutos antes de expirar
SAFETY_MARGIN = timedelta(minutes=5)


def get_access_token() -> str:
    """Retorna o access token do Azure, usando cache quando possível."""
    with _cache_lock:
        now = datetime.utcnow()

        # Verifica se o token em cache ainda é válido
        if (
            _access_token_cache["token"] and
            _access_token_cache["expires_at"] > now + SAFETY_MARGIN
        ):
            return _access_token_cache["token"]

        # Gera novo token
        client = msal.ConfidentialClientApplication(
            CLIENT_ID, authority=AUTHORITY, client_credential=CLIENT_SECRET
        )
        result = client.acquire_token_for_client(scopes=SCOPE)

        if "access_token" not in result:
            raise Exception(f"Erro ao obter token Azure: {result.get('error_description')}")

        # MSAL retorna expires_in em segundos (geralmente 3600 = 1 hora)
        expires_in = result.get("expires_in", 3600)
        _access_token_cache["token"]      = result["access_token"]
        _access_token_cache["expires_at"] = now + timedelta(seconds=expires_in)

        print(f"[PowerBI] Novo access token gerado. Expira em: {_access_token_cache['expires_at']}")
        return _access_token_cache["token"]


def _make_cache_key(report_id: str, user, has_rls: bool) -> str:
    """
    Gera a chave de cache para o embed token.
    Com RLS, o token é por usuário. Sem RLS, é compartilhado por relatório.
    """
    if has_rls and user:
        # Token com RLS é específico por usuário + relatório
        user_fingerprint = f"{user.id}_{user.role}_{user.empresa_revenda}_{user.departamento}"
        return f"embed_{report_id}_rls_{user_fingerprint}"
    else:
        # Token sem RLS pode ser compartilhado entre todos os usuários
        return f"embed_{report_id}_norls"


def _get_cached_embed(cache_key: str) -> Optional[dict]:
    """Retorna embed token do cache se ainda válido, None caso contrário."""
    with _cache_lock:
        cached = _embed_token_cache.get(cache_key)
        if cached and cached["expires_at"] > datetime.utcnow() + SAFETY_MARGIN:
            return cached
        # Remove entrada expirada
        if cached:
            del _embed_token_cache[cache_key]
        return None


def _save_embed_cache(cache_key: str, data: dict, expires_at: datetime) -> None:
    """Salva embed token no cache."""
    with _cache_lock:
        _embed_token_cache[cache_key] = {**data, "expires_at": expires_at}


def clear_embed_cache(report_id: str = None) -> None:
    """
    Limpa o cache de embed tokens.
    Se report_id for informado, limpa apenas os tokens daquele relatório.
    Útil para chamar após editar um relatório no admin.
    """
    with _cache_lock:
        if report_id:
            keys_to_delete = [k for k in _embed_token_cache if f"embed_{report_id}_" in k]
            for k in keys_to_delete:
                del _embed_token_cache[k]
            print(f"[PowerBI] Cache limpo para report_id={report_id}")
        else:
            _embed_token_cache.clear()
            print("[PowerBI] Cache de embed tokens completamente limpo")


def get_user_value(user, filter_source: str) -> Optional[str]:
    """Retorna o valor do campo do usuário conforme filter_source."""
    if filter_source == "empresa_revenda":
        return user.empresa_revenda
    elif filter_source == "departamento":
        return user.departamento
    elif filter_source == "email":
        return user.email
    return None


def get_embed_token(workspace_id: str, report_id: str,
                    user=None, has_rls: bool = False, rls_configs=None) -> dict:

    # ── Verifica cache ───────────────────────────────────────────
    cache_key = _make_cache_key(report_id, user, has_rls)
    cached    = _get_cached_embed(cache_key)
    if cached:
        print(f"[PowerBI] Embed token do cache. Expira em: {cached['expires_at']}")
        return cached

    # ── Gera novo embed token ────────────────────────────────────
    print(f"[PowerBI] Gerando novo embed token para report_id={report_id}")

    access_token = get_access_token()
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type":  "application/json"
    }

    # Busca informações do relatório (embed URL e dataset ID)
    report_url  = f"{PBI_API}/groups/{workspace_id}/reports/{report_id}"
    report_resp = requests.get(report_url, headers=headers)
    report_info = report_resp.json()
    embed_url   = report_info.get("embedUrl")
    dataset_id  = report_info.get("datasetId")

    # Monta o body do GenerateToken
    body = {"accessLevel": "view"}

    if has_rls and rls_configs and user:
        user_role   = user.role if not user.is_admin else "admin"
        matched_rls = [r for r in rls_configs if r.system_role == user_role]

        if matched_rls:
            if len(matched_rls) == 1:
                rls      = matched_rls[0]
                username = get_user_value(user, rls.filter_source) or user.email
                roles    = [rls.role_name]
                print(f"[PowerBI] RLS simples: role={roles}, username={username}")
            else:
                rls_by_source = {r.filter_source: r for r in matched_rls}
                val_revenda   = get_user_value(user, "empresa_revenda") if "empresa_revenda" in rls_by_source else ""
                val_depto     = get_user_value(user, "departamento")    if "departamento"    in rls_by_source else ""
                username      = f"{val_revenda}|{val_depto}"
                roles         = [matched_rls[0].role_name]
                print(f"[PowerBI] RLS duplo: role={roles}, username={username}")

            body["identities"] = [{
                "username": username,
                "roles":    roles,
                "datasets": [dataset_id]
            }]
        else:
            body["identities"] = [{
                "username": user.email,
                "roles":    ["admin"],
                "datasets": [dataset_id]
            }]
            print(f"[PowerBI] Acesso livre via role admin: {user.email}")

    print(f"[PowerBI] Body enviado: {body}")

    token_url  = f"{PBI_API}/groups/{workspace_id}/reports/{report_id}/GenerateToken"
    token_resp = requests.post(token_url, headers=headers, json=body)
    token_data = token_resp.json()
    print(f"[PowerBI] Token gerado. Expira em: {token_data.get('expiration')}")

    embed_token = token_data.get("token")

    # Calcula expiração do embed token (Power BI retorna ISO 8601)
    try:
        expiration_str = token_data.get("expiration", "")
        expires_at     = datetime.fromisoformat(expiration_str.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        # Fallback: 1 hora a partir de agora
        expires_at = datetime.utcnow() + timedelta(hours=1)

    result = {
        "embed_token": embed_token,
        "embed_url":   embed_url,
        "report_id":   report_id
    }

    # ── Salva no cache ───────────────────────────────────────────
    _save_embed_cache(cache_key, result, expires_at)

    return result