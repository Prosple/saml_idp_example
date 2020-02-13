<?php

class IdpProvider {

  // Defining some trusted Service Providers.
  private $trusted_sps = [
    'urn:service:provider:id' => 'https://service-provider.com/login/callback'
  ];

  /**
   * Retrieves the Assertion Consumer Service.
   *
   * @param string
   *   The Service Provider Entity Id
   * @return
   *   The Assertion Consumer Service Url.
   */
  public function getServiceProviderAcs($entityId){
    return $this->trusted_sps[$entityId];
  }

  /**
   * Returning a dummy IdP identifier.
   *
   * @return string
   */
  public function getIdPId(){
    return "https://www.idp.com";
  }

  /**
   * Retrieves the certificate from the IdP.
   *
   * @return \LightSaml\Credential\X509Certificate
   */
  public function getCertificate(){
    return \LightSaml\Credential\X509Certificate::fromFile('cert/saml_test_certificate.crt');
  }

  /**
   * Retrieves the private key from the Idp.
   *
   * @return \RobRichards\XMLSecLibs\XMLSecurityKey
   */
  public function getPrivateKey(){
    return \LightSaml\Credential\KeyHelper::createPrivateKey('cert/saml_test_certificate.key', '', true);
  }

  /**
   * Returns a dummy user email.
   *
   * @return string
   */
  public function getUserEmail(){

    return "duarte.garin@samltuts.com";
  }

}
