<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) 2014-2021 Sean Tymon <tymon148@gmail.com>
 * (c) 2021 PHP Open Source Saver
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PHPOpenSourceSaver\JWTAuth\Providers\JWT;

use DateTimeImmutable;
use Exception;
use Illuminate\Support\Collection;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as ES256;
use Lcobucci\JWT\Signer\Ecdsa\Sha384 as ES384;
use Lcobucci\JWT\Signer\Ecdsa\Sha512 as ES512;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HS256;
use Lcobucci\JWT\Signer\Hmac\Sha384 as HS384;
use Lcobucci\JWT\Signer\Hmac\Sha512 as HS512;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RS256;
use Lcobucci\JWT\Signer\Rsa\Sha384 as RS384;
use Lcobucci\JWT\Signer\Rsa\Sha512 as RS512;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use PHPOpenSourceSaver\JWTAuth\Contracts\Providers\JWT;
use PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenInvalidException;
use ReflectionClass;

class SSOLcobucci extends Provider implements JWT
{
    /**
     * The builder instance.
     *
     * @var Builder
     */
    protected $builder;

    /**
     * The configuration instance.
     *
     * @var Configuration
     */
    protected $config;

    /**
     * The Signer instance.
     *
     * @var Signer
     */
    protected $signer;

    /**
     * Create the Lcobucci provider.
     *
     * @param string        $secret
     * @param string        $algo
     * @param Configuration $config optional, to pass an existing configuration to be used
     *
     * @return void
     */
    public function __construct(
        $secret,
        $algo,
        array $keys,
        $config = null
    ) {
        parent::__construct($secret, $algo, $keys);

        $this->signer = $this->getSigner();

        if (!is_null($config)) {
            $this->config = $config;
        } elseif ($this->isAsymmetric()) {
            $this->config = Configuration::forAsymmetricSigner($this->signer, $this->getSigningKey(), $this->getVerificationKey());
        } else {
            $this->config = Configuration::forSymmetricSigner($this->signer, InMemory::plainText($this->getSecret()));
        }
        if (!count($this->config->validationConstraints())) {
            $this->config->setValidationConstraints(
                new SignedWith($this->signer, $this->getVerificationKey()),
            );
        }
    }
}
