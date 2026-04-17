import requests
import os
import msal

TENANT_ID     = os.getenv("TENANT_ID")
CLIENT_ID     = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
AUTHORITY     = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPE         = ["https://analysis.windows.net/powerbi/api/.default"]
PBI_API       = "https://api.powerbi.com/v1.0/myorg"

def get_access_token():
    app = msal.ConfidentialClientApplication(
        CLIENT_ID, authority=AUTHORITY, client_credential=CLIENT_SECRET
    )
    result = app.acquire_token_for_client(scopes=SCOPE)
    if "access_token" in result:
        return result["access_token"]
    raise Exception(f"Erro ao obter token: {result.get('error_description')}")

def get_user_value(user, filter_source):
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
    access_token = get_access_token()
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    report_url  = f"{PBI_API}/groups/{workspace_id}/reports/{report_id}"
    report_resp = requests.get(report_url, headers=headers)
    report_info = report_resp.json()
    embed_url   = report_info.get("embedUrl")
    dataset_id  = report_info.get("datasetId")

    body = {"accessLevel": "view"}

    if has_rls and rls_configs and user:
        user_role   = user.role if not user.is_admin else "admin"
        matched_rls = [r for r in rls_configs if r.system_role == user_role]

        if matched_rls:
            if len(matched_rls) == 1:
                # Filtro simples
                rls      = matched_rls[0]
                username = get_user_value(user, rls.filter_source) or user.email
                roles    = [rls.role_name]
                print(f"RLS simples: role={roles}, username={username}")

            else:
                # Filtro duplo — ordem FIXA: empresa_revenda|departamento
                # Independente da ordem cadastrada no banco
                rls_by_source = {r.filter_source: r for r in matched_rls}

                val_revenda = get_user_value(user, "empresa_revenda") \
                    if "empresa_revenda" in rls_by_source else ""
                val_depto   = get_user_value(user, "departamento") \
                    if "departamento" in rls_by_source else ""

                username = f"{val_revenda}|{val_depto}"

                # Role vem da primeira regra (todas devem usar a mesma role combinada)
                roles = [matched_rls[0].role_name]
                print(f"RLS duplo: role={roles}, username={username}")

            body["identities"] = [{
                "username": username,
                "roles":    roles,
                "datasets": [dataset_id]
            }]

        else:
            # Sem regra para essa role → acesso livre via role que vê tudo
            body["identities"] = [{
                "username": user.email,
                "roles":    ["admin"],
                "datasets": [dataset_id]
            }]
            print(f"Acesso livre via role admin: {user.email}")

    print("BODY ENVIADO:", body)

    token_url   = f"{PBI_API}/groups/{workspace_id}/reports/{report_id}/GenerateToken"
    token_resp  = requests.post(token_url, headers=headers, json=body)
    print("TOKEN JSON:", token_resp.json())
    embed_token = token_resp.json().get("token")

    return {
        "embed_token": embed_token,
        "embed_url":   embed_url,
        "report_id":   report_id
    }