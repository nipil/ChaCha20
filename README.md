# ChaCha20

[![Build Status](https://travis-ci.org/nipil/ChaCha20.svg?branch=master)](https://travis-ci.org/nipil/ChaCha20)
[![Coverage Status](https://coveralls.io/repos/github/nipil/ChaCha20/badge.svg?branch=master)](https://coveralls.io/github/nipil/ChaCha20?branch=master)

A pure-php implementation of ChaCha20, fully tested on both 32-bit php and 64 bits.

## Install

Tested on Ubuntu 16.04 LTS (with php 7.0)

basic system components :

    sudo apt-get install composer

phpunit asks for following system additional components :

    sudo apt-get install php-xml php-mbstring zip

coveralls.io asks for following system additional components :

    sudo apt-get install php-curl

additionnal package if you want to run code coverage locally :

    sudo apt-get install php-xdebug

Install with composer (dev)

    composer install

Install with composer (production)

    composer install --no-dev

Run tests with composer

    composer exec -- phpunit

Run tests with composer with local code coverage (requires xdebug, see above)

    mkdir -p build/html
    composer exec -- phpunit --coverage-text --coverage-html build/html/
