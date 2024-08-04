#!/bin/sh
php-fpm &
rc-service apache2 start
ssh-keygen -A
exec /usr/sbin/sshd -D -e "$@"