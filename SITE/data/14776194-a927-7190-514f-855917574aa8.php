<?php
return array (
  'uuid' => '14776194-a927-7190-514f-855917574aa8',
  'type' => 'contact',
  'recipients' => 'javiles@hostingred.com',
  'subject' => 'Formulario de contacto',
  'reply' => 'Su mensaje ha sido enviado. Muchas gracias.',
  'buttonText' => 'Enviar email',
  'captchaEnabled' => true,
  'visibilityMode' => 'all',
  'styles' => 
  array (
    'margin' => '0 0 0 0',
    'padding' => '5px 10px 5px 10px',
    'background' => '',
    'backgroundColor' => 'transparent',
    'backgroundPosition' => 'top left',
    'backgroundStretch' => 'tile',
    'backgroundOpacity' => '100',
    'borderRadius' => '0 0 0 0',
    'boxShadow' => 'none',
    'textColor' => 'inherit',
    'textStroke' => false,
    'linkColor' => 'inherit',
    'linkStroke' => false,
    'h1Color' => 'inherit',
    'h1Stroke' => false,
    'h2Color' => 'inherit',
    'h2Stroke' => false,
  ),
  'fields' => 
  array (
    0 => 
    array (
      'name' => 'name',
      'type' => 'textfield',
      'title' => 'Nombre',
      'required' => true,
    ),
    1 => 
    array (
      'name' => 'mail',
      'type' => 'email',
      'title' => 'Email',
      'required' => true,
    ),
    2 => 
    array (
      'name' => 'message',
      'type' => 'textarea',
      'title' => 'Mensaje',
      'required' => true,
    ),
  ),
  'badCaptcha' => 'El texto introducido no coincide con el texto proporcionado en la imagen.',
  'wrongRequest' => 'Petición errónea',
  'isPassCaptcha' => false,
  'recaptchaPrivateKey' => '6LcIkNMSAAAAAL_dH5rlWS0XsGfXg9IODumFDHeK',
);
?>