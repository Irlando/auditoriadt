# Análise de incidentes

Repositório com evidências e relatórios de análise de incidentes de segurança, organizado por pasta de caso.

## Caso `2-13.10`

O caso contém registos de endpoint, autenticação e Microsoft 365, bem como uma mensagem de e-mail usada na reconstrução da cronologia.

### Relatórios

- [Relatório completo em Markdown](./2-13.10/Relatorio_Incidente_2026-10-14.md)
- [Relatório HTML](./2-13.10/Relatorio_Incidente_2026-10-14.html)
- [Relatório Word para a direção](./2-13.10/Relatorio_Incidente_2026-10-14_Diretoria.docx)

### Evidências analisadas

- `EDR.log`
- `M365.log`
- `PC_Security.log`
- `mensagem_recebida.eml`

O relatório reúne o resumo executivo, a cronologia em UTC, o impacto observado e os limites da evidência, as medidas de contenção registadas, recomendações futuras e os hashes SHA-256 dos ficheiros de log.

## Nota de utilização

Os próprios artefactos deste caso identificam o exercício como fictício e os endereços IP como dados de documentação. O conteúdo deve ser tratado como material de análise/formação, não como confirmação de um incidente real ou como indicador operacional. Não instale ferramentas nem autorize ligações remotas com base nas instruções da mensagem incluída nas evidências.

## Integridade

Os hashes SHA-256 calculados durante a análise estão documentados na secção **Integridade dos registos** dos relatórios. Recalcule-os sobre os ficheiros originais antes de usar as evidências noutro processo; os valores registados não substituem uma cadeia de custódia formal.
