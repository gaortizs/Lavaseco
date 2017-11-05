<?php
/**
 * Simple inline resolver
 *
 * @since 2010/11/13
 * @package Module
 * @subpackage ProtectedPage
 * @copyright (c) 2004-2014. Parallels IP Holdings GmbH. All rights reserved.
 */
class Module_ProtectedPage_InlineResolver implements Zend_Auth_Adapter_Http_Resolver_Interface {

	/**
	 * Username
	 * @var string
	 */
	private $_username;

	/**
	 * Password
	 * @var string
	 */
	private $_password;

	/**
	 * Realm
	 * @var string
	 */
	private $_realm;

	/**
	 * @param array $authSettings Settings with keys: username, password, realm
	 * @param string $type basic OR digest
	 */
	public function __construct($authSettings, $type) {
		$this->_username = $authSettings['username'];

		$safeMode = ini_get('safe_mode');
		if (is_string($safeMode)) {
			$safeMode = strtolower(trim($safeMode));
			$safeMode = !empty($safeMode) && in_array($safeMode, array('on', 'yes', 'true', '1'));
		}
		$this->_realm = $safeMode
			? $authSettings['realm'] . '-' . getmyuid()
			: $authSettings['realm'];

		$this->_password = ('digest' == $type)
			? md5($authSettings['username'] . ':' . $this->_realm . ':' . $authSettings['password'])
			: $authSettings['password'];
	}

	public function resolve($username, $realm) {
		return ($username == $this->_username && $realm == $this->_realm) ? $this->_password : '';
	}

}