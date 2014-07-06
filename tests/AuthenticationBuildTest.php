<?php
namespace Opine;

class AuthenticationBuildTest extends \PHPUnit_Framework_TestCase {
    private $authentication;

    public function setup () {
        date_default_timezone_set('UTC');
        $root = __DIR__ . '/../public';
        $container = new Container($root, $root . '/../container.yml');
        $this->authentication = $container->authentication;
    }

    public function testBuild () {
        $this->assertTrue($this->authentication->build());
    }
}