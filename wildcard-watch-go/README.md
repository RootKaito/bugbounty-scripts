# Wildcard Watch (Go)

Consulta o diretório público do HackerOne e avisa sobre programas Bounty com
wildcard e eficiência de resposta mínima (70% por padrão).

## Railway

Use `wildcard-watch-go` como diretório raiz do serviço. O Dockerfile compila o
binário e o `railway.toml` agenda uma execução a cada seis horas, UTC.
Monte um volume persistente em `/data` e use apenas uma instância escrevendo no
mesmo estado.

Variáveis:

- `DISCORD_WEBHOOK_URL`: obrigatório.
- `TELEGRAM_BOT_TOKEN` e `TELEGRAM_CHAT_ID`: opcionais; configure ambos juntos.
- `MIN_RESPONSE_EFFICIENCY`: padrão `70`.
- `STATE_PATH`: padrão `/data/seen_programs.json`.

## Entrega e migração

Novos programas são persistidos antes do envio. O campo `delivery` registra a
confirmação de cada canal. Falhas ficam pendentes para a próxima execução,
inclusive se o programa deixar de passar nos filtros. Canais já confirmados
não são reenviados normalmente. Falhas de entrega fazem o processo sair com
código 1; com `restartPolicyType = "NEVER"`, a retomada ocorre no próximo cron.

Registros antigos sem `delivery` continuam considerados já entregues. O seed
embutido só inicializa volumes sem arquivo de estado. Ele não permite recuperar
alertas perdidos pela versão antiga, pois ela não registrava a entrega.

Cada requisição tem timeout de 30 segundos e até três tentativas para falhas de
rede, HTTP 429 e 5xx, com limite de dois minutos para a sequência. `Retry-After`
é respeitado; esperas maiores encerram a tentativa atual. URLs e respostas dos
canais não aparecem nos erros, pois podem conter credenciais.

A entrega não é exatamente uma vez: se o serviço aceitar uma mensagem e a
resposta se perder, ou o processo parar antes de salvar a confirmação, uma
retentativa pode duplicá-la. O estado precisa permanecer no volume.

## Validação

```sh
go test -race ./...
go vet ./...
```

O teste ao vivo é opcional, consulta somente o HackerOne e não envia alertas:

```sh
VALIDATE_LIVE=1 go test -run '^TestLiveCollection$' -v .
```
