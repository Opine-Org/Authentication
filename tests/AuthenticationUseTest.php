<?php
namespace Opine;

class AuthenticationUseTest extends \PHPUnit_Framework_TestCase {
    private $authentication;

    public function setup () {
        date_default_timezone_set('UTC');
        $root = __DIR__ . '/../public';
        $container = new Container($root, $root . '/../container.yml');
        $this->authentication = $container->authentication;
    }

    public function testBuild () {
        //$this->assertTrue($this->authentication->build());
    }

    public function testMatch () {
        $this->assertTrue(is_array($this->authentication->checkGroupUrl('/Manager')));
        $this->assertTrue(is_bool($this->authentication->checkGroupUrl('/Manager/xyz')));
        $this->assertTrue(is_array($this->authentication->checkGroupUrl('/Manager/edit/Users/users:abc123')));
    }

    public function testMatchNatural () {
        $this->assertTrue($this->authentication->checkRoute('/Manager') == 'Location: /Manager/login');
    }
}