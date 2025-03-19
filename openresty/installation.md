# api nginx installation

## install openresty
```bash
sudo apt-get update
sudo apt-get install -y curl gnupg2 ca-certificates lsb-release
curl -fsSL https://openresty.org/package/pubkey.gpg | sudo apt-key add -
codename=$(lsb_release -sc)
echo "deb http://openresty.org/package/ubuntu $codename main" | sudo tee /etc/apt/sources.list.d/openresty.list
sudo apt-get update
sudo apt-get install -y openresty
openresty -v
```

## config certification

### 1. install Certbot
```bash
# Ubuntu
sudo apt update
sudo apt install certbot
sudo apt install python3-certbot-nginx

# CentOS/RHEL
sudo yum install epel-release
sudo yum install certbot
sudo yum install certbot-nginx
```

### 2. generate certificationv

```bash
## 生成自签证书
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout server.key -out server.crt

## 生成免费生产环境证书。需要提供domain
sudo certbot --nginx
```

```bash
docker run -d -p 80:80 -p 443:443 --name openresty-container \
#  -v /path/to/nginx.conf:/usr/local/openresty/nginx/conf/nginx.conf \
#  -v /path/to/lua:/usr/local/openresty/nginx/lua \
#  -v /path/to/ssl_certificate.crt:/path/to/ssl_certificate.crt \
#  -v /path/to/ssl_certificate_key.key:/path/to/ssl_certificate_key.key \
  -e LUA_SCRIPTS_FOLDER=/usr/local/openresty/nginx/lua \
  -e SSL_CERTIFICATE=/path/to/ssl_certificate.crt \
  -e SSL_CERTIFICATE_KEY=/path/to/ssl_certificate_key.key \
  openresty -c /usr/local/openresty/nginx/conf/nginx.conf 
```