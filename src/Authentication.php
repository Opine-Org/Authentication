<?php
/**
 * Opine\Auhentication
 *
 * Copyright (c)2013,2014 Ryan Mahoney, https://github.com/Opine-Org <ryan@virtuecenter.com>
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
namespace Opine;
use FastRoute\Dispatcher\GroupCountBased;

class Authentication {
    private $db;
    private $config;
    private $yamlSlow;
    private $route;
    private $cache;
    private $routes = [];
    private $regexes = [];
    private $redirectsLogin = [];
    private $redirectsDenied = [];
    private $root;
    private $redirect = false;
    private $collector;
    private $authClassFile;
    private $authRouteFile;
    private $authData;
    private $cacheRouteData = false;

    public function __construct ($root, $db, $config, $yamlSlow, $route, $cache, $collector) {
        $this->db = $db;
        $this->config = $config;
        $this->yamlSlow = $yamlSlow;
        $this->route = $route;
        $this->root = $root;
        $this->cache = $cache;
        $this->collector = $collector;
        $this->authClassFile = $this->root . '/../cache/AclAuthData.php';
        $this->authRouteFile = $this->root . '/../cache/AclRouteData.php';
        $this->includeOnce();
    }

    private function includeOnce () {
        @include_once($this->authClassFile);
        if (class_exists('AuthData')) {
            $this->authData = new \AuthData();
        }
    }

    public function check (&$userId=false) {
        if (isset($_SESSION['user']) && isset($_SESSION['user']['_id'])) {
            $userId = $_SESSION['user']['_id'];
            return true;
        }
        return false;
    }

    private function userFindAndEstablishSession ($criteria) {
        $user = $this->db->collection('users')->findOne(
            $criteria, [
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

    public function login ($identity, $password, $identityField='email', $criteria=false) {
        if ($identityField == 'email') {
            $identity = trim(strtolower($identity));
        }
        if ($criteria === false) {
            $criteria = [
                $identityField => $identity,
                'password' => $this->passwordHash($password)
            ];
        }
        return $this->userFindAndEstablishSession($criteria);
    }

    public function loginByUserId ($userId) {
        $criteria = [
            '_id' => $this->db->id($userId)
        ];
        return $this->userFindAndEstablishSession($criteria);
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

    public function passwordHash ($password) {
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
            $this->redirectsLogin[$groupName] = $group['redirectLogin'];
            $this->redirectsDenied[$groupName] = $group['redirectDenied'];
        }
    }

    public function beforeRoute () {
        $uri = $_SERVER['REQUEST_URI'];
        $this->redirect = $uri;
        if (isset($_SERVER['QUERY_STRING']) && !empty($_SERVER['QUERY_STRING'])) {
            $uri = substr($uri, 0, ((strlen($_SERVER['QUERY_STRING']) + 1) * -1));
            $this->redirect .= '?' . $_SERVER['QUERY_STRING'];
        }
        $this->checkRoute($uri, true);
    }

    public function aclRoute () {
        if (!isset($this->routes)) {
            return;
        }
        $this->route->before('authentication@beforeRoute');
    }

    public function checkRoute ($uri, $send=true) {
        $groups = $this->checkGroupUrl($uri);
        if (!is_array($groups) || count($groups) == 0) {
            return true;
        }
        $redirectsLogin = $this->authData->login();
        $redirectsDenied = $this->authData->deny();
        if (!$this->check()) {
            $redirect = '/form/Login';
            if (isset($redirectsLogin[$groups[0]])) {
                $redirect = $redirectsLogin[$groups[0]];
            }
            if ($send === true) {
                $_SESSION['acl_redirect'] = $uri;
                $location = 'Location: ' . $redirect;
                $this->redirectAppend($location);
                @header($location);
                return $location;
            } else {
                return false;
            }
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
            if (isset($redirectsDenied[$groups[0]])) {
                $redirect = $redirectsDenied[$groups[0]];
            }
            if ($send === true) {
                $_SESSION['acl_redirect'] = $uri;
                $location = 'Location: ' . $redirect;
                $this->redirectAppend($location);
                @header($location);
                return $location;
            } else {
                return false;
            }
        }
        return true;
    }

    public function checkAndRedirect ($location) {
        if (!$this->check()) {
            $redirect = '/form/login';
            $_SESSION['acl_redirect'] = $location;
            $location = 'Location: ' . $redirect;
            $this->redirectAppend($location);
            @header($location);
            exit;
        }
        return true;
    }

    private function redirectAppend (&$location) {
        if ($this->redirect !== false) {
            if (substr_count($location, '?') > 0) {
                $location .= '&redirect=' . urlencode($this->redirect);
            } else {
                $location .= '?redirect=' . urlencode($this->redirect);
            }
        }
    }

    public function build () {
        $dirFiles = glob($this->root . '/../acl/*.yml');
        foreach ($dirFiles as $config) {
            $this->aclConfig($config);
        }
        $json = json_encode([
            'routes' => $this->routes,
            'redirectsLogin' => $this->redirectsLogin,
            'redirectsDenied' => $this->redirectsDenied
        ], JSON_PRETTY_PRINT);
        $groups = [];
        foreach (array_values($this->routes) as $values) {
            foreach ($values as $group) {
                $groups[] = $group;
            }
        }
        $groups = array_unique($groups);
        sort($groups);
        foreach ($groups as $group) {
            $this->groupCheck($group);
        }
        $buildFile = $this->root . '/../cache/acl.json';
        file_put_contents($buildFile, $json);
        $this->makeClass();
        return true;
    }

    private function makeClass () {
        $buffer = '<?php' . "\n" . 'class AuthData {' . "\n";
        foreach ($this->routes as $route => $groups) {
            $method = 'auth' . uniqid();
            $this->addGroupRegex($route, 'AuthData@' . $method);
            $buffer .= 'public function ' . $method . '() {' . "\n";
            $buffer .= "\t" . 'return ' . var_export($groups, true) . ';' . "\n";
            $buffer .= '}' . "\n\n"; 
        }
        $buffer .= 'public function login () {' . "\n";
        $buffer .= "\t" . 'return ' . var_export($this->redirectsLogin, true) . ';' . "\n";
        $buffer .= '}' . "\n\n";

        $buffer .= 'public function deny () {' . "\n";
        $buffer .= "\t" . 'return ' . var_export($this->redirectsDenied, true) . ';' . "\n";
        $buffer .= '}' . "\n\n";

        $buffer .= '}' . "\n";
        file_put_contents($this->authClassFile, $buffer);
        $this->includeOnce();
        file_put_contents(
            $this->authRouteFile,
            '<?php return ' . var_export($this->collector->getData(), true) . ';'
        );
        $key = $this->root . '-acl';
        $this->cache->set($key, json_encode($this->collector->getData()), 2, 0);
    }

    private function groupCheck ($group) {
        $check = $this->db->collection('groups')->findOne(['title' => $group]);
        if (!isset($check['_id'])) {
            $this->db->collection('groups')->save(['title' => $group]);
        }
    }

    public function cacheSet ($cacheRouteData) {
        $this->cacheRouteData = $cacheRouteData;
    }

    public function addGroupRegex ($pattern, $callback) {
        $callback = explode('@', $callback);
        $this->collector->addRoute('GET', $pattern, $callback);
    }

    public function checkGroupUrl ($uri) {
        if ($this->cacheRouteData === false) {
            $this->cacheRouteData = require $this->authRouteFile;
        }
        $dispatcher = new GroupCountBased($this->cacheRouteData);
        $route = $dispatcher->dispatch('GET', $uri);
        switch ($route[0]) {
            case \FastRoute\Dispatcher::NOT_FOUND:
                return false;

            case \FastRoute\Dispatcher::METHOD_NOT_ALLOWED:
                return false;

            case \FastRoute\Dispatcher::FOUND:
                return call_user_func_array($route[1], $route[2]);
            
            default:
                return false;
        }
    }
}