<?php
namespace Blimp\Accounts\Rest;

use Blimp\Accounts\Documents\Account;
use Blimp\Http\BlimpHttpException;
use Blimp\Accounts\Oauth2\Oauth2AccessToken;
use Blimp\Accounts\Oauth2\Protocol;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class FacebookAccessToken extends Oauth2AccessToken {
    public function getAuthorizationEndpoint() {
        return 'https://graph.facebook.com/oauth/authorize';
    }

    public function getAccessTokenEndpoint() {
        return 'https://graph.facebook.com/oauth/access_token';
    }

    public function getClientID() {
        return $this->api['config']['facebook']['client_id'];
    }

    public function getClientSecret() {
        return $this->api['config']['facebook']['client_secret'];
    }

    public function getScope() {
        return $this->api['config']['facebook']['scope'];
    }

    public function getDisplay() {
        return $this->request->query->get('display') != NULL ? $this->request->query->get('display') : 'popup';
    }

    public function getOtherAuthorizationRequestParams() {
        $redirect_url = '';

        $display = $this->getDisplay();
        if ($display != null && strlen($display) > 0) {
            $redirect_url .= '&display=' << $display;
        }

        if ($this->getForceLogin()) {
            $redirect_url .= '&auth_type=reauthenticate';
        }

        return $redirect_url;
    }

    public function requestAccessToken($code) {
        $tk = parent::requestAccessToken($code);

        if ($this->api['config']['facebook']['long_lived_access_token'] && !($tk instanceof Response) && $tk['access_token'] != null) {
            // Retrieves the Facebook long-lived access_token
            $tk = $this->getLongLivedAccessToken($tk['access_token']);
        }

        return $tk;
    }

    public function getLongLivedAccessToken($currentToken) {
        $params = [
            'grant_type' => 'fb_exchange_token',
            'client_id' => $this->getClientID(),
            'client_secret' => $this->getClientSecret(),
            'redirect_uri' => $this->request->getUriForPath($this->request->getPathInfo()),
            'fb_exchange_token' => $currentToken
        ];

        $access_token_data = Protocol::get($this->getAccessTokenEndpoint(), $params);

        return $access_token_data;
    }

    public function processAccountData($access_token) {
        if ($access_token != NULL && (!empty($access_token['access_token']) || !empty($access_token['accessToken']))) {
            /* Get profile_data */
            $params = [
                'access_token' => !empty($access_token['access_token']) ? $access_token['access_token'] : $access_token['accessToken'],
                'fields' => $this->api['config']['facebook']['fields'],
                'type' => 'small'
            ];

            $profile_data = Protocol::get('https://graph.facebook.com/me', $params);
            if($profile_data instanceof Response) {
                return $profile_data;
            }

            if ($profile_data != null && $profile_data['id'] != null) {
                if($access_token['userID'] != null && $profile_data['id'] != $access_token['userID']) {
                    throw new BlimpHttpException(Response::HTTP_UNAUTHORIZED, "Invalid access_token");
                }
                
                $id = hash_hmac('ripemd160', 'facebook-' . $profile_data['id'], 'obscure');

                $dm = $this->api['dataaccess.mongoodm.documentmanager']();

                $account = $dm->find('Blimp\Accounts\Documents\Account', $id);

                if ($account != null) {
                    $code = Response::HTTP_FOUND;
                } else {
                    $code = Response::HTTP_CREATED;
                    
                    $account = new Account();
                    $account->setId($id);
                    $account->setType('facebook');
                }
                
                $resource_uri = '/accounts/' . $account->getId();
                
                $secret = NULL;
                if($account->getOwner() == NULL) {
                    $bytes = openssl_random_pseudo_bytes(16);
                    $hex   = bin2hex($bytes);
                    $secret = password_hash($hex, PASSWORD_DEFAULT);                
                }

                $account->setBlimpSecret($secret);
                $account->setAuthData($access_token);
                $account->setProfileData($profile_data);
                
                $dm->persist($account);
                $dm->flush();

                $response = new JsonResponse((object) ["uri" => $resource_uri, "secret" => $secret], $code);
                $response->headers->set('AccountUri', $resource_uri);
                $response->headers->set('AccountSecret', $secret);

                return $response;
            } else {
                throw new BlimpHttpException(Response::HTTP_NOT_FOUND, "Resource not found");
            }
        } else {
            throw new BlimpHttpException(Response::HTTP_UNAUTHORIZED, "No access_token");
        }
    }
}
