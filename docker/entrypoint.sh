#!/bin/sh
php-fpm &
rc-service lighttpd start
ssh-keygen -A
exec /usr/sbin/sshd -D -e "$@"