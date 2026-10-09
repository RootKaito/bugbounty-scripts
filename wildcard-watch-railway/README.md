# Wildcard Watch (Railway)

Varre `hackerone.com/opportunities/all` a cada 6h, filtra programas
**Bounty** com asset **Wildcard** e response efficiency alta, e avisa no
Discord + Telegram só o que for novo desde a última execução. Roda como
cron job no Railway — sem depender da sua VM estar ligada, sem a
restrição de rede que travou a tentativa anterior via cloud routine do
Claude.

Testado com envio real em 2026-10-08 (Vercel, Arc, Wolt, Whatnot, Twilio
chegaram certinho nos dois canais).

## Por que Railway em vez da rotina na nuvem do Claude

A tentativa anterior (rotina agendada do Claude Code) bloqueava saída de
rede por padrão pra `hackerone.com` e `discord.com`. Railway é um host
comum, sem esse tipo de allowlist — roda igual rodaria na sua própria
máquina.

## Deploy

1. **Instale a CLI do Railway** (se ainda não tiver):
   ```bash
   npm i -g @railway/cli
   railway login
   ```

2. **Crie o projeto** a partir desta pasta:
   ```bash
   cd wildcard-watch-railway
   railway init
   ```

3. **Adicione um Volume** (pro estado persistir entre execuções — sem
   isso, todo run acha tudo "novo" de novo):
   - No dashboard do Railway: seu serviço → **Settings → Volumes → New Volume**
   - Mount path: `/data`

4. **Configure as variáveis de ambiente** (Settings → Variables):
   - `DISCORD_WEBHOOK_URL` — obrigatória, a URL do webhook do canal #wildcard-watch
   - `TELEGRAM_BOT_TOKEN` — opcional, token do bot (sem ela, só notifica Discord)
   - `TELEGRAM_CHAT_ID` — opcional, seu chat ID (o mesmo que já usa no resto do projeto)
   - `MIN_RESPONSE_EFFICIENCY` — opcional, default `70`

5. **Deploy:**
   ```bash
   railway up
   ```

O `railway.toml` já define o cron (`0 */6 * * *`, a cada 6h em UTC) e que
o build usa o `Dockerfile` daqui. Pra mudar a frequência, edite
`cronSchedule` nesse arquivo (sintaxe cron padrão, 5 campos, UTC) e rode
`railway up` de novo.

## Testar antes de confiar no cron

Depois do primeiro deploy, dispare uma execução manual pelo dashboard
(Deployments → ... → Redeploy) ou:
```bash
railway run python3 watch.py
```
e confira os logs — ele avisa quantos cards extraiu, quantos passaram no
filtro, quantos eram novos, e se a notificação saiu.

## Formato da notificação

```
👁️ Nyarlathotep whispers...

🎯 Vercel
🌐 2 wildcard domains
💰 $50 – $10,000
🔥 Good target

🔗 https://hackerone.com/vercel
```

## Arquivos

- `watch.py` — scraper (Playwright) + filtro + dedup + notify (Discord + Telegram)
- `Dockerfile` — imagem oficial do Playwright (Chromium já incluso)
- `railway.toml` — build + cron schedule
- `requirements.txt` — deps Python

## Local (pra testar sem subir pro Railway ainda)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
export TELEGRAM_BOT_TOKEN="123456:ABC..."   # opcional
export TELEGRAM_CHAT_ID="..."                # opcional
export STATE_PATH=/tmp/seen_programs.json
python3 watch.py
```
