<?php
/**
 * Auth adapter from provided array values
 *
 * @since 2011/05/17
 * @package Module
 * @subpackage ProtectedPage
 * @copyright (c) 2004-2014. Parallels IP Holdings GmbH. All rights reserved.
 */
class Module_ProtectedPage_ArrayAuthAdapter implements Zend_Auth_Adapter_Interface
{
	/**
	 * Auth settings
	 * @var array
	 */
	private $_settings	= null;

	/**
	 * Values, provided by user
	 * @var array
	 */
	private $_values	= null;

	public function setSettings($settings) {
		$this->_settings = $settings;
		return $this;
	}

	public function setValues($values) {
		$this->_values = $values;
		return $this;
	}

	/**
	 * @see Zend_Auth_Adapter_Interface::authenticate
	 */
	public function authenticate() {
		if (is_null($this->_settings)) {
			throw new Zend_Auth_Adapter_Exception('Auth settings isn`t set in auth adapter');
		}
		if (is_null($this->_values)) {
			throw new Zend_Auth_Adapter_Exception('Auth values isn`t set in auth adapter');
		}
		if (count($this->_settings) < 2) {
			throw new Zend_Auth_Adapter_Exception('Auth settings should have 2 values');
		}
		if (count($this->_values) < 2) {
			throw new Zend_Auth_Adapter_Exception('Auth values should have 2 values');
		}
		if ($this->_settings == $this->_values) {
			return new Zend_Auth_Result(Zend_Auth_Result::SUCCESS, reset($this->_settings));
		} else {
			return new Zend_Auth_Result(Zend_Auth_Result::FAILURE, null);
		}
	}
}