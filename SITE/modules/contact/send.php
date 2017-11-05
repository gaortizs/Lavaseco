<?php
require_once('../../includes/init.php');

$req = new Zend_Controller_Request_Http();

$config = getConfig($req->uuid);
if (empty($config)) {
	sendResponse(false);
}

if (!$config->isPassCaptcha) {
	$isCaptchaOk = false;
	try {
		$isCaptchaOk = recaptchaCheck(array(
			'privatekey' => $config->recaptchaPrivateKey,
			'remoteip' => $req->getClientIp(),
			'challenge' => $req->get('recaptcha_challenge_field'),
			'response' => $req->get('recaptcha_response_field')
		));
	} catch (Exception $e) {
		error_log($e->getMessage());
		sendResponse(false);
	}

	if (!$isCaptchaOk) {
		sendResponse(false, $config->badCaptcha, array('code' => 'badCaptcha'));
	}
}

$body = $req->getParam('message', '');
$fromEmail = null;
foreach ($config->fields as $field) {
	if (!$fromEmail && $field->type == 'email') {
		$fromEmail = $req->getParam($field->name, '');
	}

	if (in_array($field->name, array('message'))) {
		continue;
	}
	$body .= "\n{$field->title}: " . $req->getParam($field->name, '');
}

$mail = new Zend_Mail('utf-8');
$mail->addHeader('X-Mailer', 'Web Presence Builder');
$mail->setBodyText($body);

if ($fromEmail) {
	$mail->setFrom($fromEmail, $req->name ? $req->name : '');
}

$recipientArray = preg_split('/(,|;)\s*/', $config->recipients);
$mail->addTo($recipientArray);
$mail->setSubject($config->subject);
$mail->send();

sendResponse(true, $config->reply);

/**
 * Write response and terminate script
 *
 * @param bool $result
 * @param string $message
 * @param array $extra
 */
function sendResponse($result, $message = '', $extra = array()) {
	exit(Zend_Json::encode(
		(array('result' => $result, 'message' => $message)) + $extra)
	);
}

/**
 * Calls an HTTP POST function to verify if the user's guess was correct
 *
 * @param $data
 * @return bool
 */
function recaptchaCheck($data) {
	$response = recaptchaHttpPost($data);
	list($result) = explode("\n", $response[1]);
	return trim($result) == 'true';
}

/**
 * Submits an HTTP POST to a reCAPTCHA server
 *
 * @param array $data
 * @return array response
 * @throws Exception
 */
function recaptchaHttpPost($data) {
	$req = http_build_query($data);

	$http_request = "POST /recaptcha/api/verify HTTP/1.0\r\n";
	$http_request .= "Host: www.google.com\r\n";
	$http_request .= "Content-Type: application/x-www-form-urlencoded;\r\n";
	$http_request .= "Content-Length: " . strlen($req) . "\r\n";
	$http_request .= "User-Agent: reCAPTCHA/PHP\r\n";
	$http_request .= "\r\n";
	$http_request .= $req;

	$response = '';
	if (false == ($fs = @fsockopen('www.google.com', 80, $errno, $errstr, 10))) {
		throw new Exception('Could not open socket: ' . $errstr);
	}

	fwrite($fs, $http_request);

	while (!feof($fs)) {
		$response .= fgets($fs, 1160); // One TCP-IP packet
	}
	fclose($fs);

	return explode("\r\n\r\n", $response, 2);
}

/**
 * Returns config for contact module
 *
 * @param $name
 * @return null|Zend_Config
 */
function getConfig($name) {
	$configPath = './../../data/' . $name . '.php';

	if (!empty($name) && preg_match('/^[a-f0-9]{8}-([a-f0-9]{4}-){3}[a-f0-9]{12}$/', $name)
		&& is_file($configPath)) {
		return new Zend_Config(require $configPath);
	}

	return null;
}
