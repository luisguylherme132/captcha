import os
import hmac
import hashlib
import time
import logging

import requests
from flask import Flask, request, render_template_string

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("VerifyServer")

# ─────────────────────────────────────────────
# CONFIGURAÇÃO (definida no painel da Vercel: Project Settings → Environment Variables)
# ─────────────────────────────────────────────
DISCORD_TOKEN       = os.getenv("DISCORD_TOKEN")
VERIFY_SECRET       = os.getenv("VERIFY_SECRET")
HCAPTCHA_SITE_KEY   = os.getenv("HCAPTCHA_SITE_KEY")
HCAPTCHA_SECRET_KEY = os.getenv("HCAPTCHA_SECRET_KEY")
ROLE_ID             = os.getenv("ROLE_ID")

app = Flask(__name__)

DISCORD_API = "https://discord.com/api/v10"


def check_signature(uid: str, gid: str, exp: str, sig: str) -> bool:
    """Confere se o link não foi adulterado e ainda não expirou."""
    if not VERIFY_SECRET:
        return False
    try:
        if int(exp) < int(time.time()):
            return False
    except ValueError:
        return False
    msg = f"{uid}:{gid}:{exp}".encode()
    expected = hmac.new(VERIFY_SECRET.encode(), msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-br">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verificação</title>
  <script src="https://hcaptcha.com/1/api.js" async defer></script>
  <style>
    body {
      background: #0a0a0a; color: #fff; font-family: system-ui, sans-serif;
      display: flex; align-items: center; justify-content: center;
      height: 100vh; margin: 0;
    }
    .card {
      background: #141414; border: 1px solid #262626; border-radius: 16px;
      padding: 40px; max-width: 380px; text-align: center;
    }
    h1 { font-size: 20px; margin-bottom: 8px; }
    p { color: #a3a3a3; font-size: 14px; margin-bottom: 24px; }
    .h-captcha { display: flex; justify-content: center; margin-bottom: 20px; }
    button {
      background: #fff; color: #000; border: none; border-radius: 8px;
      padding: 12px 24px; font-size: 15px; font-weight: 600; cursor: pointer; width: 100%;
    }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    .msg { margin-top: 16px; font-size: 14px; }
    .msg.error { color: #f87171; }
    .msg.ok { color: #4ade80; }
  </style>
</head>
<body>
  <div class="card">
    <h1>🔒 Verificação</h1>
    <p>Complete o captcha abaixo para liberar seu acesso ao servidor.</p>
    <form id="form" method="POST">
      <input type="hidden" name="uid" value="{{ uid }}">
      <input type="hidden" name="gid" value="{{ gid }}">
      <input type="hidden" name="exp" value="{{ exp }}">
      <input type="hidden" name="sig" value="{{ sig }}">
      <div class="h-captcha" data-sitekey="{{ site_key }}"></div>
      <button type="submit">Verificar</button>
    </form>
    {% if message %}<div class="msg {{ 'ok' if ok else 'error' }}">{{ message }}</div>{% endif %}
  </div>
</body>
</html>
"""


@app.route("/verify", methods=["GET"])
def verify_page():
    uid = request.args.get("uid", "")
    gid = request.args.get("gid", "")
    exp = request.args.get("exp", "")
    sig = request.args.get("sig", "")

    if not check_signature(uid, gid, exp, sig):
        return render_template_string(
            PAGE_TEMPLATE, uid=uid, gid=gid, exp=exp, sig=sig,
            site_key=HCAPTCHA_SITE_KEY, message="❌ Link inválido ou expirado. Peça um novo no servidor.", ok=False), 400

    return render_template_string(PAGE_TEMPLATE, uid=uid, gid=gid, exp=exp, sig=sig,
                                  site_key=HCAPTCHA_SITE_KEY, message=None, ok=False)


@app.route("/verify", methods=["POST"])
def verify_submit():
    uid = request.form.get("uid", "")
    gid = request.form.get("gid", "")
    exp = request.form.get("exp", "")
    sig = request.form.get("sig", "")
    token = request.form.get("h-captcha-response", "")

    def fail(msg, status=400):
        return render_template_string(PAGE_TEMPLATE, uid=uid, gid=gid, exp=exp, sig=sig,
                                      site_key=HCAPTCHA_SITE_KEY, message=msg, ok=False), status

    if not check_signature(uid, gid, exp, sig):
        return fail("❌ Link inválido ou expirado. Peça um novo no servidor.")

    if not token:
        return fail("❌ Complete o captcha antes de enviar.")

    # ── Valida o captcha com a API do hCaptcha ──
    try:
        r = requests.post("https://hcaptcha.com/siteverify", data={
            "secret": HCAPTCHA_SECRET_KEY,
            "response": token,
        }, timeout=10)
        result = r.json()
    except Exception as ex:
        log.error(f"Erro ao validar hCaptcha: {ex}")
        return fail("❌ Erro ao validar o captcha. Tente novamente em instantes.", 502)

    if not result.get("success"):
        log.warning(f"hCaptcha falhou para uid={uid}: {result.get('error-codes')}")
        return fail("❌ Captcha inválido. Tente novamente.")

    # ── Concede o cargo via API do Discord ──
    try:
        resp = requests.put(
            f"{DISCORD_API}/guilds/{gid}/members/{uid}/roles/{ROLE_ID}",
            headers={"Authorization": f"Bot {DISCORD_TOKEN}"},
            timeout=10,
        )
    except Exception as ex:
        log.error(f"Erro ao chamar API do Discord: {ex}")
        return fail("❌ Erro ao liberar seu acesso. Fale com um administrador.", 502)

    if resp.status_code not in (200, 204):
        log.error(f"Discord API retornou {resp.status_code}: {resp.text[:300]}")
        return fail("❌ Não consegui liberar seu acesso. Verifique se o cargo do bot "
                    "está acima do cargo de verificação, e se o bot tem permissão 'Gerenciar Cargos'.", 502)

    log.info(f"✅ Cargo liberado para uid={uid} no servidor {gid}")
    return render_template_string(PAGE_TEMPLATE, uid=uid, gid=gid, exp=exp, sig=sig,
                                  site_key=HCAPTCHA_SITE_KEY,
                                  message="✅ Verificado com sucesso! Pode voltar pro Discord.", ok=True)


@app.route("/", methods=["GET"])
def index():
    return "Arrow — servidor de verificação ativo.", 200


# A Vercel invoca esse módulo procurando uma variável chamada "app" (WSGI) —
# não precisa (nem deve) rodar app.run() aqui.