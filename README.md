Goal

I investigated an intrusion on Wayne Enterprises’ website (http://www.imreallynotbatman.com) using Splunk and OSINT. I reconstructed the attacker’s activity, identified the compromise vector, and collected all relevant artifacts (IOCs).

Investigation steps
Initial discovery

I started by searching for all events related to the domain:

index=botsv1 imreallynotbatman.com


In Suricata logs I observed alerts tied to the CVE-2014-6271 (Shellshock) vulnerability.

Attacker reconnaissance

I identified IP 40.80.148.42 performing automated scanning of the site. The user-agent strings and request patterns indicated use of Acunetix.
To confirm traffic volume by source, I ran:

index=botsv1 sourcetype=stream* | stats count(src_ip) as Requests by src_ip | sort - Requests


This showed that 40.80.148.42 generated a large number of requests.

Brute-force and admin access

I inspected POST requests to the Joomla admin panel:

index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php" form_data=*username*passwd*


I found a brute-force campaign from 23.22.63.114 with 412 unique password attempts. The attacker succeeded logging in as admin using the password batman.

Malware upload and execution

After gaining access I found an uploaded executable 3791.exe. Its MD5 is:

AAE3F5A29935E6ABCC2C2754D12A9AF0


Threat intel indicated this sample is a known trojan (also observed as ab.exe). I also found another sample, MirandaTateScreensaver.scr.exe, MD5:

c99131e0169171935c5ac32615ed6261

Site defacement

I discovered the file used for defacement: poisonivy-is-coming-for-you-batman.jpeg, which was fetched from the domain prankglassinebracket.jumpingcrab.com. OSINT on the infrastructure revealed a likely contact email lillian.rose@po1s0n1vy.com.

Artifacts & IOCs

IP addresses

40.80.148.42 (scanning)

23.22.63.114 (brute-force)

192.168.250.70 (victim)

Domains

prankglassinebracket.jumpingcrab.com

www.po1s0n1vy.com

Files / Hashes

3791.exe — MD5: AAE3F5A29935E6ABCC2C2754D12A9AF0

MirandaTateScreensaver.scr.exe — MD5: c99131e0169171935c5ac32615ed6261

poisonivy-is-coming-for-you-batman.jpeg

Credentials

username: admin

password: batman

What I traced (summary)

Reconnaissance by an automated scanner (Acunetix).

Exploitation activity tied to CVE-2014-6271 observed in IDS logs.

Brute-force against Joomla admin endpoint, successful login as admin.

Upload and execution of malicious binaries on the web server.

Download of the defacement image from attacker-controlled infrastructure and site defacement.

These actions map across the Cyber Kill Chain stages: Reconnaissance → Weaponization/Delivery → Exploitation → Installation → Command & Control → Actions on Objectives.

Recommendations (actions I would take)

Isolate 192.168.250.70 and capture full forensic images and logs.

Block 23.22.63.114 and 40.80.148.42 at the perimeter.

Remove malicious files and restore site from verified clean backups.

Create detections for the observed file hashes and the brute-force patterns against /joomla/administrator/index.php.

Patch and update Joomla; restrict admin access (IP allowlist, 2FA, CAPTCHA).

Push IOCs to EDR/AV and network defenses (hashes, domains, IPs).

Harden monitoring: alert on unexpected outbound connections from web servers and on file uploads to web directories.



Objetivo

Investiguei uma intrusão no site da Wayne Enterprises (http://www.imreallynotbatman.com) usando Splunk e OSINT. Reconstituí as atividades do atacante, identifiquei o vetor de comprometimento e coletei todos os artefatos relevantes (IOCs).

Etapas da investigação
Descoberta inicial

Comecei buscando todos os eventos relacionados ao domínio:

index=botsv1 imreallynotbatman.com


Nos logs do Suricata observei alertas vinculados à vulnerabilidade CVE-2014-6271 (Shellshock).

Reconhecimento do atacante

Identifiquei o IP 40.80.148.42 realizando varredura automatizada do site. As strings de User-Agent e o padrão de requisições indicaram uso do Acunetix.
Para confirmar o volume de tráfego por origem, executei:

index=botsv1 sourcetype=stream* | stats count(src_ip) as Requests by src_ip | sort - Requests


Isso mostrou que 40.80.148.42 gerou grande número de requisições.

Brute-force e acesso à admin

Inspecionei requisições POST ao painel administrativo do Joomla:

index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php" form_data=*username*passwd*


Encontrei uma campanha de brute-force originada do IP 23.22.63.114 com 412 tentativas únicas de senha. O atacante obteve acesso logando como admin com a senha batman.

Upload e execução de malware

Após obter acesso, localizei um executável carregado, 3791.exe. O MD5 dele é:

AAE3F5A29935E6ABCC2C2754D12A9AF0


Inteligência de ameaças indicou que essa amostra é um trojan conhecido (também observado como ab.exe). Encontrei também outra amostra: MirandaTateScreensaver.scr.exe, MD5:

c99131e0169171935c5ac32615ed6261

Defacement do site

Descobri o arquivo usado no defacement: poisonivy-is-coming-for-you-batman.jpeg, baixado do domínio prankglassinebracket.jumpingcrab.com. A investigação OSINT na infraestrutura revelou um contato provável: lillian.rose@po1s0n1vy.com.

Artefatos & IOCs

Endereços IP

40.80.148.42 (varredura)

23.22.63.114 (brute-force)

192.168.250.70 (vítima)

Domínios

prankglassinebracket.jumpingcrab.com

www.po1s0n1vy.com

Arquivos / Hashes

3791.exe — MD5: AAE3F5A29935E6ABCC2C2754D12A9AF0

MirandaTateScreensaver.scr.exe — MD5: c99131e0169171935c5ac32615ed6261

poisonivy-is-coming-for-you-batman.jpeg

Credenciais

usuário: admin

senha: batman

O que eu rastreei (resumo)

Reconhecimento com scanner automatizado (Acunetix).

Atividade de exploração associada à CVE-2014-6271 observada nos logs do IDS.

Brute-force contra o endpoint admin do Joomla, login bem-sucedido como admin.

Upload e execução de binários maliciosos no servidor web.

Download da imagem de defacement a partir da infraestrutura controlada pelo atacante e defacement do site.

Essas ações cobrem estágios da Cyber Kill Chain: Reconnaissance → Weaponization/Delivery → Exploitation → Installation → Command & Control → Actions on Objectives.

Recomendações (ações que eu tomaria)

Isolar 192.168.250.70 e capturar imagens forenses completas e logs.

Bloquear 23.22.63.114 e 40.80.148.42 no perímetro.

Remover arquivos maliciosos e restaurar o site a partir de backups verificados.

Criar deteções para os hashes observados e para padrões de brute-force contra /joomla/administrator/index.php.

Aplicar patches e atualizar Joomla; restringir acesso à admin (whitelist de IP, 2FA, CAPTCHA).

Distribuir IOCs para EDR/AV e defesas de rede (hashes, domínios, IPs).

Reforçar monitoramento: alertar sobre conexões de saída inesperadas de servidores web e uploads de arquivos para diretórios web.
