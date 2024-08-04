#From PHP8.3-cli
FROM php:8.3-fpm-alpine

RUN adduser -h /home/admin -s /home/admin/vendor/bin/phpterminal -D admin
RUN echo -n 'admin:admin' | chpasswd

WORKDIR /home/admin/

RUN apk update
RUN apk add --update --no-cache git
RUN apk add --update --no-cache zip
RUN apk add --update --no-cache vim
RUN apk add --update --no-cache openssh
RUN apk add --update --no-cache openrc
RUN apk add --update --no-cache apache2
RUN apk add --update --no-cache apache2-proxy
RUN apk add --update --no-cache php83-apache2
RUN apk add --update --no-cache shadow
RUN mkdir -p /run/openrc/exclusive
RUN touch /run/openrc/softlevel
RUN rc-update add apache2

RUN docker-php-ext-configure pcntl --enable-pcntl && docker-php-ext-install pcntl
RUN docker-php-ext-configure bcmath --enable-bcmath && docker-php-ext-install bcmath

RUN cat <<EOF > /etc/apache2/conf.d/phpfirewall.conf
<VirtualHost *:80>
    DocumentRoot /home/admin/public/

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

    ProxyPassMatch ^/(.*\.php(/.*)?)$ fcgi://127.0.0.1:9000/home/admin/public/$1
    DirectoryIndex /index.php index.php

    <Directory /home/admin/public/>
        Options -Indexes
        AllowOverride All
        Order allow,deny
        allow from all
    </Directory>
</VirtualHost>
<IfModule unixd_module>
User admin
Group admin
</IfModule>
EOF

RUN php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
RUN php composer-setup.php
RUN php -r "unlink('composer-setup.php');"
RUN mv composer.phar /home/admin/composer
RUN chmod +x /home/admin/composer
RUN /home/admin/composer require oyeaussie/phpfirewall
ENV COMPOSER_ALLOW_SUPERUSER=1

RUN echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
RUN echo 'Port 2233' >> /etc/ssh/sshd_config
ENTRYPOINT ["/entrypoint.sh"]
COPY entrypoint.sh /

RUN echo 'user = admin' >> /usr/local/etc/php-fpm.d/www.conf
RUN echo 'group = admin' >> /usr/local/etc/php-fpm.d/www.conf

RUN mkdir /home/admin/terminaldata
RUN mkdir /home/admin/firewalldata
RUN mkdir /home/admin/public

COPY index.php ./public/
RUN chown -R admin:admin /home/admin
# Running
# docker run -d --name phpfirewall -h phpfirewall oyeaussie/phpfirewall
# Grab IP
# docker exec phpfirewall cat /etc/hosts | grep phpfirewall
# {container IP}    phpfirewall
# Connect via ssh
# ssh -l admin -p 2233 {container IP}