<?php

/**
 * Copyright (c) 2010-2017 Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Eureka\Component\User;

use Eureka\Component\Config\Config;
use Eureka\Component\Http\Session;
use Eureka\Component\Mcrypt\Mcrypt;
use Eureka\Component\Password\Password;
use Eureka\Component\User\Exception\UserNotFoundException;
use Eureka\Interfaces\Bag\BagInterface;

/**
 * Class User
 *
 * @author Romain Cottard
 */
class User implements UserLoginInterface
{
    /**
     * @var string $key Encryption key for data in session.
     */
    private $key = '';

    /**
     * @var string $sessionKeyData
     */
    private $sessionKeyId = 'component.user.id';

    /**
     * @var string $sessionKeyAuth
     */
    private $sessionKeyAuth = 'component.user.is_authenticated';

    /**
     * @var BagInterface $session
     */
    private $session = null;

    /**
     * @var int $id User ID
     */
    private $id = 0;

    /**
     * @var mixed $data User data.
     */
    private $data = null;

    /**
     * @var bool $isAuthenticated
     */
    private $isAuthenticated = false;

    /**
     * User constructor.
     *
     * @param $mapper
     */
    public function __construct(BagInterface $session, $key = 'eureka-enc-default-key')
    {
        $this->session = $session;
        $this->key     = $key;

        $this->restoreFromSession();
    }

    /**
     * Get user id.
     *
     * @return int
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * User data.
     *
     * @return mixed
     */
    public function getData()
    {
        return $this->data;
    }

    /**
     * User data.
     *
     * @param  int   $userId
     * @param  mixed $userData
     * @return void
     */
    public function setData($userId, $userData)
    {
        $this->id   = (int) $userId;
        $this->data = $userData;

        $this->persistInSession();

        return $this;
    }

    /**
     * @return boolean
     */
    public function isAuthenticated()
    {
        return $this->isAuthenticated;
    }

    /**
     * Login a user.
     *
     * @param  string $login
     * @param  string $passwordPlainText
     * @param  string $passwordHash
     * @return $this
     * @throws UserAuthenticationException
     * @throws UserNotFoundException
     */
    public function login($login, $passwordPlainText, $passwordHash)
    {
        $password = new Password($passwordPlainText);
        if (!$password->verify($passwordHash)) {
            throw new UserAuthenticationException();
        }

        $this->isAuthenticated = true;

        return $this;
    }

    /**
     * Logout a user.
     *
     * @return void
     */
    public function logout()
    {
        $this->id              = 0;
        $this->isAuthenticated = false;
        $this->data            = null;

        $this->persistInSession();

        return $this;
    }

    /**
     * Persiste user data in session.
     * Plain password must be not save in session !
     *
     * @return $this
     */
    private function persistInSession()
    {
        $this->session->set($this->sessionKeyId, $this->encrypt($this->id));
        $this->session->set($this->sessionKeyAuth, $this->isAuthenticated);
    }

    /**
     * Restore data from session.
     *
     * @return $this
     */
    private function restoreFromSession()
    {
        if (!$this->session->has($this->sessionKeyAuth)) {
            $this->session->set($this->sessionKeyAuth, false);
        }

        $this->isAuthenticated = $this->session->get($this->sessionKeyAuth);

        if (!$this->session->has($this->sessionKeyId)) {
            $this->id = 0;

            return $this;
        }

        $this->id = (int) $this->decrypt($this->session->get($this->sessionKeyId));

        if ($this->id === 0) {
            $this->isAuthenticated = false;
        }
    }

    /**
     * Encrypt data
     *
     * @param  mixed $data
     * @return string
     */
    private function encrypt($data)
    {
        $mcrypt = $this->getMcrypt();

        $data = $mcrypt->encrypt(base64_encode(json_encode($data)));
        $encryptedData = base64_encode($mcrypt->getIV().$data);

        return $encryptedData;
    }

    /**
     * Decrypt data
     *
     * @param  string $encryptedData
     * @return mixed
     */
    private function decrypt($encryptedData)
    {
        $data = base64_decode($encryptedData);

        $mcrypt = $this->getMcrypt();
        $mcrypt->setIV(substr($data, 0, $mcrypt->getSizeIV()));
        $data = $mcrypt->decrypt(substr($data, $mcrypt->getSizeIV()));

        return json_decode(base64_decode($data));
    }

    /**
     * Get mcrypt new instance
     *
     * @return Mcrypt
     */
    private function getMcrypt()
    {
        return (new Mcrypt())->setKey($this->key);
    }
}