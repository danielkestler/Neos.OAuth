<?php
declare(strict_types=1);

namespace Neos\OAuth\Domain\Model;

enum TokenType: string
{
    case ACCESS_TOKEN = 'access_token';
    case REFRESH_TOKEN = 'refresh_token';
    case AUTH_CODE = 'auth_code';
}
