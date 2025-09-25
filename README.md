# jdwx/acme-php

A PHP client for the ACME protocol (e.g. Let's Encrypt).

## Installation

You can require it directly with Composer:

```bash
composer require jdwx/acme
```

Or download the source from GitHub: https://github.com/jdwx/acme-php.git

## Requirements

This module requires PHP 8.3 or later.

## Usage

This module provides a client for the ACME protocol, which is used by certificate authorities like Let's Encrypt to automate the process of domain validation and certificate issuance.

The module is quite complicated and usable documentation hasn't been developed yet.

A command-line utility is provided in
`bin/acme-cli.php` which can be used to perform common operations like registering an account, creating orders, completing challenges, and downloading certificates.

## Stability

This module has supported the issuance of hundreds of thousands of certificates in production. There are now two independent practical implementations of ACMEv2 certificate issuance based on this module in production use.

## History

This module was used extensively internally for over a year before being publicly released in September 2025.
