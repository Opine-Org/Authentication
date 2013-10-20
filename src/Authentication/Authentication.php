<?php
namespace Authentication;

class Authentication {
	private $db;
	private $separation;
	private $response;

	public function __construct ($db, $config, $separation, $response) {
		$this->db = $db;
		$this->separation = $separation;
		$this->response = $response;
	}

	public function valid ($name) {
		if (!isset($_SESSION['auth']) { {
			return false;
		}
		if (!isset($_SESSION['auth'][$name]) {
			return false;
		}
		if (!isset($_SESSION['auth'][$name]['status'])) {
			return false;
		}
		if ($_SESSION['auth'][$name]['status'] !== true) {
			return false;
		}
		return true;
	}

	public function login ($name) {
		$db->collection('users')->findOne(

		);
	}

	public function passwordForgot () {

	}

	public function passwordChange () {

	}
}