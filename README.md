# ChaCha20

[![Build Status](https://travis-ci.org/nipil/ChaCha20.svg?branch=master)](https://travis-ci.org/nipil/ChaCha20)
[![Coverage Status](https://coveralls.io/repos/github/nipil/ChaCha20/badge.svg?branch=master)](https://coveralls.io/github/nipil/ChaCha20?branch=master)

A pure-php implementation of ChaCha20, fully tested on both 32-bit php and 64 bits.

## Install

Tested on Ubuntu 16.04 LTS (with php 7.0)

phpunit asks for following system components :

    sudo apt-get install composer php-xml php-mbstring zip

Install with composer

    composer install

Run tests with composer

    composer exec phpunit
