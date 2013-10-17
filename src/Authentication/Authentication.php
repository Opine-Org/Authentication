<?php
namespace Authentication;

class Authentication {
	private $db;
	private $separation;
	private $response;

	public function __construct ($db, $separation, $response) {
		$this->db = $db;
		$this->separation = $separation;
		$this->response = $response;
	}

	public function valid () {
		return true;
	}
}