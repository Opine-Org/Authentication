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
	private $yamlSlow;
	private $slim;
	private $cache;
	private $routes = [];
	private $regexes = [];
	private $redirectsLogin = [];
	private $redirectsDenied = [];
	private $root;

	public function __construct ($root, $db, $config, $yamlSlow, $slim, $cache) {
		$this->db = $db;
		$this->config = $config;
		$this->yamlSlow = $yamlSlow;
		$this->slim = $slim;
		$this->root = $root;
		$this->cache = $cache;
	}

	public function authenticatedCheck () {
		if (isset($_SESSION['user']) && isset($_SESSION['user']['_id'])) {
			return true;
		}
		return false;
	}

	public function login ($identity, $password, $identityField='email') {
//FIXME: rate limit...
		if ($identityField == 'email') {
			$identity = trim(strtolower($identity));
		}
		$user = $this->db->collection('users')->findOne(
			[
				$identityField => $identity,
				'password' => $this->passwordHash($password)
			], [
				'_id', 
				'email', 
				'first_name', 
				'last_name', 
				'groups', 
				'created_date',
				'image',
				'groups'
			]);
		if (!isset($user['_id'])) {
			return false;
		}
		$_SESSION['user'] = $user;
		$this->db->collection('login_history')->save([
			'user_id' => $user['_id'],
			'created_date' => new \MongoDate(strtotime('now'))
		]);
		return true;
	}

	public function permission ($group) {
		if (!isset($_SESSION['user']) || !isset($_SESSION['user']['groups'])) {
			return false;
		}
		if (in_array('superadmin', $_SESSION['user']['groups'])) {
			return true;
		}
		if (in_array($group, $_SESSION['user']['groups'])) {
			return true;
		}
		return false;
	}

	public function logout () {
		$_SESSION['user'] = [];
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

	private function aclConfig ($configFile) {
		if (function_exists('yaml_parse_file')) {
			$config = yaml_parse_file($configFile);
		} else {
			$config = $this->yamlSlow->parse($configFile);
		}
		if ($config == false) {
			throw new \Exception('Can not parse ACL YAML file: ' . $configFile);
		}
		if (isset($config['imports']) && is_array($config['imports']) && !empty($config['imports'])) {
			foreach ($config['imports'] as $import) {
				$first = substr($import, 0, 1);
				if ($first != '/') {
					$import = $this->root . '/../' . $import;
				}
				$this->aclConfig($import);
			}
		}
		if (!isset($config['groups']) || !is_array($config['groups'])) {
			return;
		}
		foreach ($config['groups'] as $groupName => $group) {
			if (isset($group['routes']) && is_array($group['routes'])) {
				foreach ($group['routes'] as $route) {
					if (!isset($this->routes[$route])) {
						$this->routes[$route] = [];
					}
					$this->routes[$route][] = $groupName;
				}
			}
			if (isset($group['regexes']) && is_array($group['regexes'])) {
				foreach ($group['regexes'] as $regex) {
					if (!isset($this->regexes[$regex])) {
						$this->regexes[$regex] = [];
					}
					$this->regexes[$regex][] = $groupName;
				}
			}
			$this->redirectsLogin[$groupName] = $group['redirectLogin'];
			$this->redirectsDenied[$groupName] = $group['redirectDenied'];
		}
	}

	public function aclRoute () {
		if (!isset($this->routes)) {
			return;
		}
		$routes = array_keys($this->routes);
		$regexes = array_keys($this->regexes);
		$this->slim->hook('slim.before.dispatch', function () use ($routes, $regexes) {
			$pattern = $this->slim->router()->getCurrentRoute()->getPattern();
			$groups = [];
			if (in_array($pattern, $routes)) {
				$groups = $this->routes[$pattern];
			} elseif (count($regexes) > 0) {
				try {
					foreach ($regexes as $regex) {
						if (preg_match($regex, $pattern)) {
							$groups = $this->regexes[$regex];
							break; 
						}
					}
				} catch (\Exception $e) {
					echo $e->getMessage(), ': ', $regex, ' ', $pattern;
					exit;
				}
			} else {
				return;
			}
			if (count($groups) == 0) {
				return;
			}
			if (!$this->authenticatedCheck()) {
				$redirect = '/form/login';
				if (isset($this->redirectsLogin[$groups[0]])) {
					$redirect = $this->redirectsLogin[$groups[0]];
				}
				header('Location: ' . $redirect);
				exit;
			}
			$authorized = false;
			foreach ($groups as $group) {
				if ($this->permission($group)) {
					$authorized = true;
					break;
				}
			}
			if ($authorized !== true) {
				$redirect = '/noaccess';
				if (isset($this->redirectsDenied[$groups[0]])) {
					$redirect = $this->redirectsDenied[$groups[0]];
				}
				header('Location: ' . $redirect);
				exit;
			}
		});
	}

	public function build () {
		$dirFiles = glob($this->root . '/../acl/*.yml');
		foreach ($dirFiles as $config) {
			$this->aclConfig($config);
		}
		$json = json_encode([
			'regexes' => $this->regexes,
			'routes' => $this->routes,
			'redirectsLogin' => $this->redirectsLogin,
			'redirectsDenied' => $this->redirectsDenied
		], JSON_PRETTY_PRINT);
		$key = $this->root . '-acl.json';
		$this->cache->set($key, $json, 2, 0);
		$buildFile = $this->root . '/../acl/_build.json';
		file_put_contents($buildFile, $json);
	}

	public function cacheSet ($auth) {
		$this->regexes = $auth['regexes'];
		$this->routes = $auth['routes'];
		$this->redirectsLogin =	$auth['redirectsLogin'];
		$this->redirectsDenied = $auth['redirectsDenied'];
	}
}