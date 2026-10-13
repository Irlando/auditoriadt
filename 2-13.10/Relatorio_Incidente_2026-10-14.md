# Relatório de incidente

**Referência:** INC-2026-014  
**Data do incidente:** 14/10/2026  
**Período analisado:** 14/10/2026, 09:40–10:40 UTC  
**Ativo principal:** PC07 (198.51.100.27), utilizador Erick  
**Classificação:** Acesso remoto não autorizado, com potencial exposição de informação financeira  
**Estado:** Contenção registada; investigação de impacto e recuperação ainda necessárias  

## 1. Resumo executivo

Os registos analisados descrevem uma campanha de engenharia social dirigida ao utilizador Erick. Uma mensagem que se fazia passar por uma equipa de manutenção urgente instruiu-o a instalar o AnyDesk, aceitar uma ligação remota e manter abertas as sessões do Windows e do Microsoft 365. O EDR regista a instalação e o início do serviço AnyDesk no PC07, seguidos de uma sessão de controlo interativo aceite às 10:10 UTC, com origem indicada como `102.90.79.73` (Nigéria).

Durante a sessão, a conta `erick@visionware.pt` usou uma sessão Microsoft 365 diferente da sessão inicial e descarregou **100 ficheiros financeiros do SharePoint**, entre as 10:15:00 e as 10:31:30 UTC. Os registos indicam **28 750 000 bytes** (cerca de 27,4 MiB). O EDR confirma a criação local de quatro dos ficheiros descarregados. Estes eventos demonstram acesso e download para a sessão/estação, mas **não demonstram, por si só, que os ficheiros tenham sido enviados para o operador externo**.

O SOC isolou o PC07 às 10:34:05 UTC; a sessão AnyDesk terminou um segundo depois. Às 10:35 UTC foram revogadas as sessões de início de sessão da conta e, às 10:36 UTC, a conta foi desativada. Não há, no material analisado, evidência de execução de malware, persistência para além do serviço AnyDesk, transferência dos ficheiros para um destino externo, ou atividade posterior à contenção. A ausência de registo não prova que essas ações não tenham ocorrido.

**Nota de contexto:** o anexo da mensagem declara explicitamente que o exercício é fictício e que não contém software executável. Os endereços `198.51.100.x` pertencem a um bloco reservado para documentação e os dados parecem sanitizados/de formação. Por conseguinte, este relatório descreve a narrativa evidenciada no conjunto fornecido; não deve ser tratado como confirmação de um incidente real nem os indicadores como infraestrutura operacional.

## 2. Âmbito e metodologia

Foram analisados os ficheiros existentes em `2-13.10`:

- `EDR.log` — processos, ficheiros, rede, sessão remota e isolamento;
- `M365.log` — autenticação, acessos e downloads do Microsoft 365/SharePoint;
- `PC_Security.log` — eventos de autenticação Windows;
- `mensagem_recebida.eml` — cabeçalhos, texto da mensagem e anexo codificado.

Os horários abaixo são apresentados em **UTC**, conforme o sufixo `Z` dos registos. O período de 09:40–10:40 UTC corresponde à primeira e última atividade relevante disponível no conjunto; não representa necessariamente a duração total do incidente. A avaliação cruza os eventos pelos horários, utilizador, estação e objetos registados.

## 3. Cronologia reconstruída

| Data/hora (UTC) | Evidência e interpretação |
|---|---|
| 14/10, 09:40–09:44 | `PC_Security.log` regista, em cinco estações (PC02–PC07), um evento de falha de início de sessão Windows (4625) seguido de sucesso (4624, tipo 2) 20 segundos depois. Isoladamente, esta sequência não demonstra atividade maliciosa nem permite associá-la ao operador remoto. |
| 14/10, 09:46–09:50 | O M365 regista logins dos cinco utilizadores a partir de IPs indicados como Portugal, com MFA aceite. Para Erick, este login corresponde à sessão `S-ER01`. |
| 14/10, 10:00 | É entregue a Erick a mensagem “Manutenção obrigatória do PC”, de `ator_malicioso@onion`, com o anexo `Procedimento_Manutencao_PC.txt`. A mensagem cria urgência e pede que o utilizador instale AnyDesk, aceite a ligação e mantenha o Microsoft 365 aberto. |
| 14/10, 10:02–10:04 | O M365 regista acesso à mensagem; o EDR regista a abertura do e-mail e a criação/abertura do procedimento no PC07. |
| 14/10, 10:06–10:08 | O AnyDesk é instalado, iniciado e registado como serviço no PC07. |
| 14/10, 10:10 | É aceite a sessão remota AnyDesk `RA-014`, em modo de controlo interativo, com peer IP `102.90.79.73`, geolocalizado no registo como Nigéria. A geolocalização, por si só, não identifica a pessoa nem comprova a origem física. |
| 14/10, 10:11–10:14 | É iniciado o Edge; o EDR regista ligação a `login.microsoftonline.com`. Às 10:12, o M365 regista novo login de Erick (`S-ER02`), com `mfa=not_recorded`, seguido de acesso a documentos financeiros. A ausência de registo de MFA não prova que o MFA tenha sido contornado. |
| 14/10, 10:15–10:21:30 | O M365 regista download de **40 faturas** (8 820 000 bytes no total). O EDR regista no PC07 a criação local de `Fatura_2026_001.pdf` (201 000 bytes). |
| 14/10, 10:21:40–10:24:50 | O M365 regista download de **20 recibos** (3 210 000 bytes). O EDR regista a criação local de `Recibo_2026_001.pdf` (151 000 bytes). |
| 14/10, 10:25:00–10:28:10 | O M365 regista download de **20 notas de crédito** (2 610 000 bytes). |
| 14/10, 10:28:20–10:29:50 | O M365 regista download de **10 extratos** (8 055 000 bytes). O EDR regista a criação local de `Extrato_Conta_2026_001.xlsx` (801 000 bytes). |
| 14/10, 10:30:00–10:31:30 | O M365 regista download de **10 mapas de pagamentos** (6 055 000 bytes). O EDR regista a criação local de `Mapa_Pagamentos_Fornecedores_2026_010.xlsx` (610 000 bytes). |
| 14/10, 10:33:00–10:33:30 | O M365 regista novo acesso à mensagem por Erick; o EDR confirma atividade de controlo interativo AnyDesk ainda ativa. |
| 14/10, 10:34:00–10:34:06 | O SOC solicita o isolamento do PC07 às 10:34:00; o isolamento tem sucesso às 10:34:05. A sessão AnyDesk termina às 10:34:06, com motivo `device_isolated`. |
| 14/10, 10:35–10:36 | O M365 regista a revogação das sessões de Erick (concluída) e a desativação da conta, ambas associadas ao ticket `INC-2026-014`. |
| 14/10, 10:38–10:40 | Surgem eventos de rotina de outro utilizador; no registo disponível não há atividade posterior de Erick nem da sessão remota. |

## 4. Impacto observado e limites da evidência

### Acessos e transferências registados

O M365 regista **100 operações `FileDownloaded` bem-sucedidas**, todas associadas à conta `erick@visionware.pt`, à sessão `S-ER02` e ao IP cliente `198.51.100.27`:

| Categoria | Ficheiros | Bytes registados |
|---|---:|---:|
| Faturas | 40 | 8 820 000 |
| Recibos | 20 | 3 210 000 |
| Notas de crédito | 20 | 2 610 000 |
| Extratos | 10 | 8 055 000 |
| Mapas de pagamentos | 10 | 6 055 000 |
| **Total** | **100** | **28 750 000** |

O EDR regista quatro ficheiros financeiros criados localmente no PC07, coincidentes em nome e tamanho com quatro operações M365. Os restantes 96 downloads constam do M365, mas a sua criação local não está demonstrada pelos eventos EDR fornecidos.

### O que não é possível concluir

- Não há nos registos fornecidos evento de upload, envio por e-mail, cópia para armazenamento externo ou outro comprovativo de exfiltração para o operador.
- A sessão de controlo remoto interativo e os downloads em sequência tornam plausível a exposição dos documentos ao operador, mas **não provam que este os tenha recebido ou conservado**.
- Não há inventário do conteúdo ou classificação dos documentos; o potencial impacto financeiro/privacidade deve ser confirmado com os proprietários da informação.
- O login M365 `S-ER02` usa o IP local indicado como Portugal, enquanto o AnyDesk identifica um peer nigeriano. Os registos não demonstram que o login M365 tenha sido feito a partir desse peer.
- Os eventos Windows de outras estações e contas não permitem confirmar, com esta evidência, comprometimento adicional.

## 5. Medidas aplicadas (evidenciadas)

1. **Isolamento do PC07 pelo SOC** solicitado às 10:34:00 e concluído com sucesso às 10:34:05 UTC, no ticket `INC-2026-014`.
2. **Terminação da sessão AnyDesk** às 10:34:06 UTC em consequência do isolamento.
3. **Revogação das sessões de início de sessão de Erick** às 10:35 UTC, com estado `completed`.
4. **Desativação da conta de Erick** às 10:36 UTC (`account_enabled=false`).

Não há evidência nos ficheiros de que tenham sido efetuadas outras ações de resposta, como reimagem do endpoint, redefinição da palavra-passe, análise forense ou notificação dos titulares dos dados. Estas ações não devem ser consideradas concluídas sem confirmação independente.

## 6. Recomendações futuras

### Prioridade imediata

1. Manter PC07 isolado e preservar uma imagem forense, memória disponível, registos do AnyDesk, artefactos do navegador e evidências Microsoft 365 antes de qualquer limpeza ou reinstalação.
2. Alterar a palavra-passe de Erick por canal confiável, verificar métodos de autenticação/MFA e rever sessões, tokens, aplicações OAuth, regras de caixa de correio e métodos de recuperação. Reativar a conta apenas após validação do SOC.
3. Confirmar com os responsáveis de SharePoint e finanças a identidade, sensibilidade e âmbito dos 100 ficheiros; verificar acessos posteriores, partilhas, sincronizações e eventuais alterações ou pagamentos relacionados.
4. Procurar no tenant e nos endpoints a mesma mensagem, remetente, assunto, anexos, instalação/execução do AnyDesk e indicadores associados; confirmar se outros utilizadores receberam ou seguiram instruções semelhantes.
5. Determinar se ocorreu qualquer transferência para fora do ambiente através dos registos de rede, proxy, DNS, firewall, telemetria EDR e registos locais do AnyDesk. Preservar os resultados e atualizar a avaliação de impacto.
6. Aplicar o processo de notificação interna, jurídica e de privacidade caso a análise confirme exposição de dados pessoais ou informação regulada.

### Reforço preventivo

- Restringir a instalação e execução de ferramentas de acesso remoto a software aprovado; bloquear ou exigir autorização administrativa para ferramentas não geridas.
- Exigir MFA resistente a phishing e rever políticas de acesso condicional, gestão de sessões e autenticação para SharePoint/Microsoft 365.
- Configurar alertas para downloads em massa, sequências anómalas de ficheiros financeiros e criação de sessões em dispositivos não conformes.
- Reforçar a filtragem de e-mail, análise de anexos e deteção de domínios/remetentes suspeitos, sem depender apenas de indicadores facilmente alteráveis.
- Reforçar formação e procedimentos: pedidos de manutenção devem ser validados por um canal independente; utilizadores não devem instalar ferramentas nem aceitar ligações remotas a pedido de mensagens inesperadas.
- Rever a cobertura e sincronização temporal de EDR, Windows e auditoria M365, para que eventos de autenticação, atividade remota e operações de ficheiros possam ser correlacionados.

## 7. Integridade dos registos — SHA-256

Hashes calculados sobre os ficheiros de log originais existentes em `2-13.10`. Estes valores identificam o conteúdo no momento da análise; não substituem uma cadeia de custódia formal.

| Ficheiro | SHA-256 |
|---|---|
| `EDR.log` | `082DBA6F7620B487889346630BD08C50B73927BC39020140EF62DFCC0FBAD635` |
| `M365.log` | `BB5B1AA211BD625BB998557F1806C6626A45CBB2152CB0405AFD392300188B0C` |
| `PC_Security.log` | `D7A296BFC85A7A2164DB83338383735AAF53BA3C1086BA5D0130866BDA60FA5D` |

## 8. Conclusão

A evidência suporta uma sequência de engenharia social que levou à instalação e utilização de acesso remoto interativo no PC07, seguida de uma sessão Microsoft 365 de Erick que descarregou 100 documentos financeiros. O endpoint e a conta foram contidos por isolamento, revogação de sessões e desativação da conta. A extensão da possível exposição está confirmada em termos de ficheiros descarregados no tenant, mas a exfiltração externa, a visualização pelo operador e o impacto final permanecem por determinar. A investigação deve continuar com preservação forense e validação independente dos registos e documentos afetados.
