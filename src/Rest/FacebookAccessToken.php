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

    public function processAccountData(array $access_token) {
        if ($access_token != NULL && $access_token['access_token'] != NULL) {
            /* Get profile_data */
            $params = [
                'access_token' => $access_token['access_token'],
                'fields' => $this->api['config']['facebook']['fields'],
                'type' => 'small'
            ];

            $profile_data = Protocol::get('https://graph.facebook.com/me', $params);
            if($profile_data instanceof Response) {
                return $profile_data;
            }

            if ($profile_data != null && $profile_data['id'] != null) {
                $id = 'facebook-' . $profile_data['id'];
                $profile_url = $profile_data['link'];
                $mug = 'https://graph.facebook.com/' . $profile_data['id'] . '/picture?type=large';

                $account = new Account();
                $account->setId($id);
                $account->setType('facebook');
                $account->setAuthData($access_token);
                $account->setProfileData($profile_data);

                $dm = $this->api['dataaccess.mongoodm.documentmanager']();

                $check = $dm->find('Blimp\Accounts\Documents\Account', $id);

                $resource_uri = '/accounts/' . $account->getId();

                if ($check != null) {
                    $response = new JsonResponse((object) ["uri" => $resource_uri], Response::HTTP_FOUND);
                    $response->headers->set('Location', $resource_uri);

                    return $response;
                }

                $dm->persist($account);
                $dm->flush();

                $response = new JsonResponse((object) ["uri" => $resource_uri], Response::HTTP_CREATED);
                $response->headers->set('Location', $resource_uri);

                return $response;
            } else {
                throw new KRestException(KHTTPResponse::NOT_FOUND, KEXCEPTION_RESOURCE_NOT_FOUND, profile_data);
            }
        } else {
            throw new KRestException(KHTTPResponse::UNAUTHORIZED, KEXCEPTION_FACEBOOK_ACCESS_DENIED);
        }
    }
}
