<?php

include "inc.php";
include "src/Utility/IdpProvider.php";
include "src/Utility/IdpTools.php";

// Initiating our IdP Provider dummy connection.
$idpProvider = new IdpProvider();

// Instantiating our Utility class.
$idpTools = new IdpTools();

// Receive the HTTP Request and extract the SAMLRequest.
$request = \Symfony\Component\HttpFoundation\Request::createFromGlobals();
$saml_request = $idpTools->readSAMLRequest($request);

// Getting a few details from the message like ID and Issuer.
$issuer = $saml_request->getMessage()->getIssuer()->getValue();
$id = $saml_request->getMessage()->getID();

// Simulate user information from IdP
$user_id = $request->get("username");
$user_email = $idpProvider->getUserEmail();

// Construct a SAML Response.
$response = $idpTools->createSAMLResponse($idpProvider, $user_id, $user_email, $issuer, $id);

// Prepare the POST binding (form).
$bindingFactory = new \LightSaml\Binding\BindingFactory();
$postBinding = $bindingFactory->create(\LightSaml\SamlConstants::BINDING_SAML2_HTTP_POST);
$messageContext = new \LightSaml\Context\Profile\MessageContext();
$messageContext->setMessage($response);

// Ensure we include the RelayState.
$message = $messageContext->getMessage();
$message->setRelayState($request->get('RelayState'));
$messageContext->setMessage($message);

// Return the Response.
/** @var \Symfony\Component\HttpFoundation\Response $httpResponse */
$httpResponse = $postBinding->send($messageContext);
print $httpResponse->getContent();
