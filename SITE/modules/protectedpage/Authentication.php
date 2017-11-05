<?php
require_once dirname(__FILE__) . '/../../includes/init.php';

/**
 * Authentication module
 *
 * @since 2010/11/14
 * @package Module
 * @subpackage ProtectedPage
 * @copyright (c) 2004-2014. Parallels IP Holdings GmbH. All rights reserved.
 */
class Module_ProtectedPage_Authentication {

	/**
	 * Auth settings
	 * @var array
	 */
	private $_settings;

	/**
	 * Messages
	 * @var array
	 */
	private $_messages;

	/**
	 * Labels
	 * @var array
	 */
	private $_labels;

	/**
	 * @param array $settings Settings with keys: username, password, realm, accessDenied
	 */
	function __construct($settings) {
		$this->_settings = $settings;
		$this->_messages = $this->_settings['messages'];
		$this->_labels   = $this->_settings['labels'];

		$this->_isCgi() ? $this->cgiAction() : $this->defaultAction();
	}

	/**
	 * Fixes REQUEST_URI variable for the case, when webserver don't give us it and PHP generates it wrong.
	 * For example in PHP under ISAPI at IIS 7.
	 */
	private function _fixUpRequestUri() {
		$isNeedFix	= (isset($_SERVER['HTTP_AUTHORIZATION']) && isset($_SERVER['REQUEST_URI'])
					&& false === strpos($_SERVER['HTTP_AUTHORIZATION'], $_SERVER['REQUEST_URI'])
					&& false !== stripos($_SERVER['REQUEST_URI'], 'index.php'));
		if ($isNeedFix) {
			$_SERVER['REQUEST_URI'] = str_ireplace('index.php', '', $_SERVER['REQUEST_URI']);
		}
	}

	/**
	 * Detects when we are under CGI
	 *
	 * @return boolean
	 */
	private function _isCgi() {
		return stristr(PHP_SAPI, 'cgi') !== false;
	}

	/**
	 * Detects preview mode of Parallels Panels
	 *
	 * @param Zend_Controller_Request_Http $request
	 * @return boolean
	 */
	private function _isShowPreviewMessage(Zend_Controller_Request_Http $request) {
		if (!$this->_messages['previewDetected']) {
			return false;
		}

		$remoteIp = $request->getServer('REMOTE_ADDR');

		return (
			$remoteIp == $request->getServer('SERVER_ADDR') ||
			$remoteIp == $request->getServer('LOCAL_ADDR') ||
			$remoteIp == gethostbyname($request->getServer('SERVER_NAME'))
		);
	}

	public function defaultAction() {
		$this->_fixUpRequestUri();

		$request			= new Zend_Controller_Request_Http();
		if ($this->_isShowPreviewMessage($request)) {
			die('<h1>' . $this->_messages['previewDetected'] . '</h1>');
		}

		$response			= new Zend_Controller_Response_Http();
		$authAdapter		= new Zend_Auth_Adapter_Http(array(
			'accept_schemes'	=> 'digest',
			'realm'				=> $this->_settings['realm'],
			'digest_domains'	=> '/',
			'nonce_timeout'		=> 3600,
		));

		require_once 'InlineResolver.php';
		$authAdapter
			->setRequest($request)
			->setResponse($response)
			->setDigestResolver(new Module_ProtectedPage_InlineResolver($this->_settings, 'digest'));

		$authResult = $authAdapter->authenticate();
		$response->sendHeaders();

		if (!$authResult->isValid()) {
			$view = new Zend_View(array(
				'scriptPath' => dirname(__FILE__)
			));
			$view->message = $this->_messages['accessDenied'];
			$html = $view->render('accessDenied.phtml');
			die($html);
		}
	}

	/**
	 * Provides CGI downgrade in the form of simple HTML form + post + session
	 */
	public function cgiAction() {
		$request	= new Zend_Controller_Request_Http();
		Zend_Session::setOptions(array(
			'cookie_lifetime'	=> 0,
			'name'				=> 'sbpp',
		));
		$auth		= Zend_Auth::getInstance();
		$credentials= array(
			'username' => $this->_settings['username'],
			'password' => $this->_settings['password'],
		);
		$auth->setStorage(new Zend_Auth_Storage_Session('sbpp_' . md5(serialize($credentials))));
		if ($auth->hasIdentity()) {
			return;
		}
		$view 		= new Zend_View(array(
			'scriptPath' => dirname(__FILE__)
		));
		$form		= new Zend_Form();
		$form->setMethod('post')
			->setView($view)
			->addElement('text', 'username', array(
				'label'			=> $this->_labels['username'] . ':',
				'placeholder' 	=> $this->_labels['username'],
			))
			->addElement('password', 'password', array(
				'label'			=> $this->_labels['password'] . ':',
				'placeholder' 	=> $this->_labels['password'],
			))
			->addElement('submit', 'login', array(
				'ignore'	=> true,
				'label'		=> $this->_labels['login'],
			));
		if ($request->isPost()) {
			require_once 'ArrayAuthAdapter.php';
			$adapter = new Module_ProtectedPage_ArrayAuthAdapter();
			$form->isValid($request->getPost());
			$adapter->setValues($form->getValues())->setSettings($credentials);
			$result  = $auth->authenticate($adapter);
			if ($result->isValid()) {
				return;
			} else {
				$view->message = $this->_messages['accessDenied'];
				$html = $view->render('accessDenied.phtml');
				die($html);
			}
		}
		$view->form		= $form;
		$view->title	= $this->_labels['title'];
		$html			= $view->render('cgi.phtml');
		die($html);
	}
}