<?php

/**
 * Copyright (c) 2010-2017 Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Eureka\Component\User;

/**
 * Interface User
 *
 * @author Romain Cottard
 */
interface UserLoginInterface
{
    /**
     * Login a user.
     *
     * @param  string $login
     * @param  string $passwordPlainText
     * @param  string $passwordHash
     * @return void
     * @throws UserAuthenticationException
     * @throws UserNotFoundException
     */
    public function login($login, $passwordPlainText, $passwordHash);

    /**
     * Logout a user.
     *
     * @return void
     */
    public function logout();
}