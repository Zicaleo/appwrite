<?php

namespace Appwrite\Auth\OAuth2;

use Appwrite\Auth\OAuth2;

// Reference Material
// [DOCS FROM OAUTH PROVIDER]

class Wechat extends OAuth2
{
    private string $endpoint = 'https://api.weixin.qq.com/sns/oauth2/';
    private string $resourceEndpoint = 'https://api.weixin.qq.com/sns/userinfo';
    protected array $user = [];
    protected array $tokens = [];
    protected array $scopes = [
        "snsapi_userinfo"
    ];
    protected string $openid = "";
    protected string $unionid = "";

    public function getName(): string
    {
        return 'wechat';
    }

    public function getLoginURL(): string
    {
        return 'https://open.weixin.qq.com/connect/qrconnect?' .
            \http_build_query([
                'appid' => $this->appID,
                'redirect_uri' => $this->callback,
                'response_type' => 'code',
                'scope' => \implode(' ', $this->getScopes()),
                'state' => \json_encode($this->state)
            ]) . '#wechat_redirect';
    }

    protected function getTokens(string $code): array
    {
        if (empty($this->tokens)) {
            // TODO: Fire request to oauth API to generate access_token
            // Make sure to use '$this->getScopes()' to include all scopes properly
            $result = \json_decode($this->request(
                'POST',
                $this->endpoint . 'access_token?' . \http_build_query([
                    'appid' => $this->appID,
                    "secret" => $this->appSecret,
                    "code" => $code,
                    "grant_type" => "authorization_code"
                ])
            ), true);
            $this->tokens[] = $result;
            $this->openid = $result->openid;
            $this->unionid = $result->unionid;
        }

        return $this->tokens;
    }

    public function refreshTokens(string $refreshToken): array
    {
        $this->tokens = \json_decode($this->request(
            'POST',
            $this->endpoint . 'refresh_token?' . \http_build_query([
                'appid' => $this->appID,
                "grant_type" => "refresh_token",
                "refresh_token" => $refreshToken
            ])
        ), true);

        if (empty($this->tokens['refresh_token'])) {
            $this->tokens['refresh_token'] = $refreshToken;
        }

        return $this->tokens;
    }

    public function getUserID(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        // TODO: Pick user ID from $user response
        $userId = $user['openid'] ?? '';

        return $userId;
    }

    public function getUserEmail(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        // TODO: No email address can be retrieved from Wechat API, so make something up here
        $userEmail = $user['unionid'] != null ? $user['unionid'] . '@wechat.com' : '';

        return $userEmail;
    }

    public function isEmailVerified(string $accessToken): bool
    {
        $user = $this->getUser($accessToken);

        // TODO: Pick user verification status from $user response
        $isVerified = $user['unionid'] != null;

        return $isVerified;
    }

    public function getUserName(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        // TODO: Pick username from $user response
        $username = $user['nickname'] ?? '';

        return $username;
    }

    protected function getUser(string $accessToken): array
    {
        if (empty($this->user)) {
            $response = \json_decode($this->request(
                'GET',
                $this->resourceEndpoint . '?' . \http_build_query([
                    'access_token' => $accessToken,
                    'openid' => $this->openid
                ])
            ), true);

            $this->user = $response['data']['0'] ?? [];
        }

        return $this->user;
    }
}