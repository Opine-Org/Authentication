<?php
/**
 * virtuecenter\authentication
 *
 * Copyright (c)2013 Ryan Mahoney, https://github.com/virtuecenter <ryan@virtuecenter.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
namespace Authentication;

class Authentication {
	private $db;
	private $config;

	public function __construct ($db, $config) {
		$this->db = $db;
		$this->config = $config;
	}

	public function valid ($zone) {
		if (!isset($_SESSION['auth'])) {
			return false;
		}
		if (!isset($_SESSION['auth'][$zone])) {
			return false;
		}
		if (!isset($_SESSION['auth'][$zone]['status'])) {
			return false;
		}
		if ($_SESSION['auth'][$zone]['status'] !== true) {
			return false;
		}
		return $_SESSION['auth'][$zone]['_id'];
	}

	public function login ($zone, $identity, $password, $identityField='email') {
//FIXME: rate limit...
		if ($identityField == 'email') {
			$identity = trim(strtolower($identity));
		}
		$user = $this->db->collection('users')->findOne(
			[
				$identityField => $identity,
				'password' => $this->passwordHash($password),
				'acl.zone' => $zone
			], [
				'_id', 
				'email', 
				'first_name', 
				'last_name', 
				'acl', 
				'created_date',
				'image'
			]);
		if (!isset($user['_id'])) {
			return false;
		}
		$access = false;
		$aclZone = [];
		foreach ($user['acl'] as $acl) {
			if ($acl['zone'] != $zone) {
				continue;
			}
			if (!isset($acl['acl']) || !is_array($acl['acl']) || count($acl['acl']) == 0) {
				continue;
			}
			$access = true;
			$aclZone = $acl;
			break;
		}
		if ($access === false) {
			return false;
		}
		if (!isset($_SESSION['auth'])) {
			$_SESSION['auth'] = [];
		}
		$_SESSION['auth'][$zone] = [];
		$_SESSION['auth'][$zone]['status'] = true;
		$_SESSION['auth'][$zone]['_id'] = (string)$user['_id'];
		$_SESSION['auth'][$zone]['acl'] = $aclZone;
		$_SESSION['auth'][$zone]['user'] = $user;
		$this->db->collection('login_history')->save([
			'user_id' => $user['_id'],
			'created_date' => new \MongoDate(strtotime('now')),
			'zone' => $zone
		]);
		return true;
	}

	public function whoami ($zone) {
		if (!isset($_SESSION['auth'])) {
			$_SESSION['auth'] = [];
			return false;
		}
		if (!isset($_SESSION['auth'][$zone])) {
			return false;
		}
		if (!isset($_SESSION['auth'][$zone]['user'])) {
			return false;
		}
		return $_SESSION['auth'][$zone]['user'];
	}

	public function permission ($zone, $access) {
		if (!isset($_SESSION['auth'])) {
			$_SESSION['auth'] = [];
			return false;
		}
		if (!isset($_SESSION['auth'][$zone])) {
			return false;
		}
		if (!isset($_SESSION['auth'][$zone]['acl'])) {
			return false;
		}
		if (in_array('superadmin', $_SESSION['auth'][$zone]['acl'])) {
			return true;
		}
		if (in_array($access, $_SESSION['auth'][$zone]['acl'])) {
			return true;
		}
		return false;
	}

	public function logout ($zone) {
		if (!isset($_SESSION['auth'])) {
			$_SESSION['auth'] = [];
		}
		$_SESSION['auth'][$zone] = [];
		return true;
	}

	private function passwordHash ($password) {
		$config = $this->config->auth;
		return sha1($config['salt'] . $password);
	}

	public function passwordForgot ($email) {
		//validate user
		//enforce rate limit
		//generate token
		//email via topic
	}

	public function passwordChange ($id, $token, $password) {
		//validate token
		//change password, remove token
	}
}