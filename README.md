# nginx-hardening-shield

🛡️ Configurações avançadas de segurança e boas práticas para fortalecer servidores web Nginx contra ataques comuns, exploits e tráfego malicioso.

> **Projeto de Estudos**: Este repositório foi criado com o objetivo de estudar e compartilhar conhecimentos sobre segurança em servidores web Nginx. As configurações e práticas aqui apresentadas são resultado de pesquisas e experimentos, visando criar um ambiente mais seguro para aplicações web.

## 🔑 Principais Recursos

- Bloqueio de injeções SQL e ataques comuns a banco de dados
- Prevenção contra tentativas de inclusão/injeção de arquivos
- Bloqueio de exploits e vulnerabilidades web comuns
- Filtragem de spam e bots maliciosos
- Bloqueio de user agents suspeitos
- Limitação avançada de taxa de requisições
- Otimização de headers de segurança
- Proteção contra DoS/DDoS
- Restrições para upload de arquivos
- Fortalecimento de SSL/TLS

## 📋 Índice

- [Configuração Básica](#configuração-básica)
- [Configurações de Segurança](#configurações-de-segurança)
  - [Bloqueio de Exploits](#bloqueio-de-exploits)
  - [Limitação Avançada de Taxa](#limitação-avançada-de-taxa)
  - [Segurança de Headers](#segurança-de-headers)
  - [Proteção de Upload](#proteção-de-upload)
  - [Fortalecimento SSL](#fortalecimento-ssl)
- [Instalação](#instalação)
- [Contribuindo](#contribuindo)

## 🔧 Configuração Básica

1. Instalação do Nginx:
```bash
apt update
apt install nginx
```

2. Faça backup da configuração atual:
```bash
cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
```

## 🛡️ Configurações de Segurança

### Bloqueio de Exploits

Adicione estas configurações ao seu arquivo de virtual host (`/etc/nginx/sites-available/seu-site`):

```nginx
# Proteção Básica contra DDoS
limit_req_zone $binary_remote_addr zone=one:10m rate=1r/s;
limit_conn_zone $binary_remote_addr zone=addr:10m;

server {
    # Configurações Básicas
    server_tokens off;  # Oculta a versão do Nginx
    autoindex off;     # Desativa listagem de diretórios
    
    # Bloqueio de Injeções SQL
    set $block_sql_injections 0;
    if ($query_string ~ "union.*select.*\(") {
        set $block_sql_injections 1;
    }
    if ($query_string ~ "union.*all.*select.*") {
        set $block_sql_injections 1;
    }
    if ($query_string ~ "concat.*\(") {
        set $block_sql_injections 1;
    }
    if ($block_sql_injections = 1) {
        return 403;  # Retorna Forbidden
    }

    # Proteção Aprimorada contra Injeção de Arquivos
    set $block_file_injections 0;
    if ($query_string ~ "[a-zA-Z0-9_]=http://") {
        set $block_file_injections 1;
    }
    if ($query_string ~ "[a-zA-Z0-9_]=(\.\.//?)+") {
        set $block_file_injections 1;
    }
    if ($query_string ~ "[a-zA-Z0-9_]=/([a-z0-9_.]//?)+") {
        set $block_file_injections 1;
    }
    if ($query_string ~ "\.(sh|bash|pl|php|cgi|asp|aspx)") {
        set $block_file_injections 1;
    }
    if ($block_file_injections = 1) {
        return 403;
    }

    # Bloqueio Avançado de Exploits
    set $block_common_exploits 0;
    if ($query_string ~ "(<|%3C).*script.*(>|%3E)") {
        set $block_common_exploits 1;
    }
    if ($query_string ~ "GLOBALS(=|\[|\%[0-9A-Z]{0,2})") {
        set $block_common_exploits 1;
    }
    if ($query_string ~ "_REQUEST(=|\[|\%[0-9A-Z]{0,2})") {
        set $block_common_exploits 1;
    }
    if ($query_string ~ "proc/self/environ") {
        set $block_common_exploits 1;
    }
    if ($query_string ~ "mosConfig_[a-zA-Z_]{1,21}(=|\%3D)") {
        set $block_common_exploits 1;
    }
    if ($query_string ~ "base64_(en|de)code\(.*\)") {
        set $block_common_exploits 1;
    }
    if ($query_string ~ "(exec|shell|system|passthru|chr|wget|curl)") {
        set $block_common_exploits 1;
    }
    if ($block_common_exploits = 1) {
        return 403;
    }

    # Bloqueio Aprimorado de Spam
    set $block_spam 0;
    if ($query_string ~ "\b(ultram|unicauca|valium|viagra|vicodin|xanax|ypxaieo)\b") {
        set $block_spam 1;
    }
    if ($query_string ~ "\b(erections|hoodia|huronriveracres|impotence|levitra|libido)\b") {
        set $block_spam 1;
    }
    if ($query_string ~ "\b(ambien|blue\spill|cialis|cocaine|ejaculation|erectile)\b") {
        set $block_spam 1;
    }
    if ($query_string ~ "\b(lipitor|phentermin|pro[sz]ac|sandyauer|tramadol|troyhamby)\b") {
        set $block_spam 1;
    }
    if ($block_spam = 1) {
        return 403;
    }

    # Bloqueio Avançado de User Agents
    set $block_user_agents 0;
    if ($http_user_agent ~ (Indy|Baiduspider|Chaos|Mate|Moon|Evil|sucker|steal|sh3ll|hack|damn|ninja|foo|bar|spider|crawl|heritrix|nikto|scanner|tools|loader|spy|curl|wget)) {
        set $block_user_agents 1;
    }
    if ($http_user_agent ~ "librwww-perl") {
        set $block_user_agents 1;
    }
    if ($http_user_agent ~ "GetRight|GetWeb!|Go!Zilla|Download Demon|Go-Ahead-Got-It|TurnitinBot|GrabNet") {
        set $block_user_agents 1;
    }
    if ($block_user_agents = 1) {
        return 403;
    }
}
```

### Limitação Avançada de Taxa

```nginx
# Configuração de Rate Limiting
http {
    # Define zonas de limitação
    limit_req_zone $binary_remote_addr zone=generic:10m rate=2r/s;
    limit_req_zone $binary_remote_addr zone=critical:10m rate=1r/s;
    
    # Limitação de conexões
    limit_conn_zone $binary_remote_addr zone=perip:10m;
    limit_conn_zone $server_name zone=perserver:10m;

    server {
        # Aplica limitação para todas as locações
        location / {
            limit_req zone=generic burst=5 nodelay;
            limit_conn perip 10;
            limit_conn perserver 100;
        }

        # Limites mais restritos para áreas administrativas
        location /admin {
            limit_req zone=critical burst=3 nodelay;
            limit_conn perip 5;
        }
    }
}
```

### Segurança de Headers

```nginx
# Headers de Segurança
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()";

# Tamanhos de Buffer
client_body_buffer_size 1k;
client_header_buffer_size 1k;
client_max_body_size 1k;
large_client_header_buffers 2 1k;
```

### Proteção de Upload

```nginx
# Restrição de Tipos de Arquivo para Upload
location ~ \.php$ {
    location ~ /uploads/.*\.php$ {
        deny all;
    }
}

# Limites de Tamanho para Upload
client_max_body_size 10M;

# Prevenção de Permissão de Execução
location ~* /(uploads|files)/.*\.(html|htm|php|js|swf)$ {
    deny all;
}
```

### Fortalecimento SSL

```nginx
# Configuração SSL
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
```

## 🚀 Instalação

1. Clone este repositório:
```bash
git clone https://github.com/seuusuario/nginx-hardening-shield.git
```

2. Copie as configurações para seu diretório Nginx:
```bash
cd nginx-hardening-shield
cp configs/* /etc/nginx/conf.d/
```

3. Teste a configuração:
```bash
nginx -t
```

4. Reinicie o Nginx:
```bash
systemctl restart nginx
```

## 🔍 Testando a Segurança

Use estas ferramentas para testar sua configuração de segurança:

- [Mozilla Observatory](https://observatory.mozilla.org/)
- [SSL Labs Server Test](https://www.ssllabs.com/ssltest/)
- [Security Headers](https://securityheaders.com/)

## 💡 Explicação das Configurações

### Bloqueio de SQL Injection
- Bloqueia tentativas de injeção SQL através de parâmetros na URL
- Detecta padrões como "UNION SELECT" e outras técnicas comuns
- Retorna código 403 (Forbidden) para requisições suspeitas

### Proteção contra Injeção de Arquivos
- Previne upload e execução de arquivos maliciosos
- Bloqueia tentativas de path traversal
- Restringe tipos de arquivos permitidos

### Bloqueio de Exploits Comuns
- Proteção contra XSS (Cross-Site Scripting)
- Bloqueio de tentativas de inclusão remota de arquivos
- Prevenção contra execução de código malicioso

### Rate Limiting
- Limita número de requisições por IP
- Proteção contra ataques de força bruta
- Configurações específicas para áreas sensíveis

## 📝 Contribuindo

Contribuições são bem-vindas! Sinta-se à vontade para enviar um Pull Request.

## ⚠️ Aviso Legal

Este é um projeto de estudos e as configurações são fornecidas como estão. Sempre teste em um ambiente de desenvolvimento antes de aplicar em produção e ajuste de acordo com suas necessidades específicas.

## 📚 Recursos Adicionais

- [Documentação Oficial do Nginx](http://nginx.org/en/docs/)
- [Nginx Security Guide](https://www.nginx.com/resources/wiki/start/topics/examples/dynamic_ssi/)
- [OWASP Nginx Security](https://owasp.org/www-pdf-archive/Nginx_security_guide.pdf)

## 🔒 Observações de Segurança

1. Estas configurações são um ponto de partida para segurança
2. Mantenha sempre seu Nginx atualizado
3. Monitore regularmente seus logs
4. Realize auditorias de segurança periódicas
5. Adapte as configurações ao seu caso de uso
