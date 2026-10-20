include /etc/nginx/security.inc;
add_header Cache-Control "no-store" always;

proxy_http_version 1.1;
proxy_set_header Connection "";
proxy_set_header Host $host;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_connect_timeout 3s;
proxy_send_timeout 10s;
proxy_read_timeout 20s;
client_max_body_size 64k;
