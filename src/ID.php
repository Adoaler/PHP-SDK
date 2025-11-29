<?php
/**
 * Adoaler ID SDK for PHP - OAuth 2.0 / OpenID Connect
 * 
 * @package Adoaler\ID
 * @version 2.0.0
 */

namespace Adoaler;

class IDConfig
{
    public string $clientId;
    public string $clientSecret;
    public string $redirectUri;
    public string $baseUrl;
    public array $scopes;
    public int $timeout;

    public function __construct(
        string $clientId,
        string $clientSecret,
        string $redirectUri,
        string $baseUrl = 'https://id.adoaler.com',
        array $scopes = ['openid', 'profile', 'email'],
        int $timeout = 30
    ) {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->redirectUri = $redirectUri;
        $this->baseUrl = $baseUrl;
        $this->scopes = $scopes;
        $this->timeout = $timeout;
    }
}

class TokenResponse
{
    public string $accessToken;
    public string $tokenType;
    public int $expiresIn;
    public ?string $refreshToken;
    public ?string $idToken;
    public ?string $scope;

    public function __construct(array $data)
    {
        $this->accessToken = $data['access_token'] ?? '';
        $this->tokenType = $data['token_type'] ?? 'Bearer';
        $this->expiresIn = $data['expires_in'] ?? 3600;
        $this->refreshToken = $data['refresh_token'] ?? null;
        $this->idToken = $data['id_token'] ?? null;
        $this->scope = $data['scope'] ?? null;
    }

    public function isExpired(): bool
    {
        return false; // Would need to track creation time
    }
}

class UserInfo
{
    public string $sub;
    public ?string $name;
    public ?string $email;
    public bool $emailVerified;
    public ?string $picture;
    public ?string $locale;

    public function __construct(array $data)
    {
        $this->sub = $data['sub'] ?? '';
        $this->name = $data['name'] ?? null;
        $this->email = $data['email'] ?? null;
        $this->emailVerified = $data['email_verified'] ?? false;
        $this->picture = $data['picture'] ?? null;
        $this->locale = $data['locale'] ?? null;
    }
}

class AdoalerID
{
    private IDConfig $config;
    private array $pkceStore = [];

    public function __construct(IDConfig $config)
    {
        $this->config = $config;
    }

    /**
     * Generate PKCE code verifier
     */
    public static function generateCodeVerifier(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    /**
     * Generate PKCE code challenge
     */
    public static function generateCodeChallenge(string $verifier): string
    {
        $hash = hash('sha256', $verifier, true);
        return rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');
    }

    /**
     * Generate random state
     */
    public static function generateState(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * Get authorization URL
     */
    public function getAuthorizationUrl(string $state, bool $usePKCE = true): array
    {
        $params = [
            'client_id' => $this->config->clientId,
            'redirect_uri' => $this->config->redirectUri,
            'response_type' => 'code',
            'scope' => implode(' ', $this->config->scopes),
            'state' => $state,
        ];

        $verifier = null;
        if ($usePKCE) {
            $verifier = self::generateCodeVerifier();
            $challenge = self::generateCodeChallenge($verifier);
            $params['code_challenge'] = $challenge;
            $params['code_challenge_method'] = 'S256';
            $this->pkceStore[$state] = $verifier;
        }

        $url = $this->config->baseUrl . '/oauth/authorize?' . http_build_query($params);

        return [
            'url' => $url,
            'state' => $state,
            'verifier' => $verifier,
        ];
    }

    /**
     * Exchange authorization code for tokens
     */
    public function exchangeCode(string $code, string $state): TokenResponse
    {
        $params = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'client_id' => $this->config->clientId,
            'client_secret' => $this->config->clientSecret,
            'redirect_uri' => $this->config->redirectUri,
        ];

        if (isset($this->pkceStore[$state])) {
            $params['code_verifier'] = $this->pkceStore[$state];
            unset($this->pkceStore[$state]);
        }

        $response = $this->postRequest('/oauth/token', $params);
        return new TokenResponse($response);
    }

    /**
     * Refresh access token
     */
    public function refreshToken(string $refreshToken): TokenResponse
    {
        $params = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => $this->config->clientId,
            'client_secret' => $this->config->clientSecret,
        ];

        $response = $this->postRequest('/oauth/token', $params);
        return new TokenResponse($response);
    }

    /**
     * Get user info
     */
    public function getUserInfo(string $accessToken): UserInfo
    {
        $response = $this->getRequest('/oauth/userinfo', $accessToken);
        return new UserInfo($response);
    }

    /**
     * Revoke token
     */
    public function revokeToken(string $token): bool
    {
        $params = [
            'token' => $token,
            'client_id' => $this->config->clientId,
            'client_secret' => $this->config->clientSecret,
        ];

        try {
            $this->postRequest('/oauth/revoke', $params);
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Get logout URL
     */
    public function getLogoutUrl(string $idToken, ?string $postLogoutRedirect = null): string
    {
        $params = ['id_token_hint' => $idToken];
        
        if ($postLogoutRedirect) {
            $params['post_logout_redirect_uri'] = $postLogoutRedirect;
        }

        return $this->config->baseUrl . '/oauth/logout?' . http_build_query($params);
    }

    /**
     * Store verifier in session
     */
    public function storeVerifierInSession(string $state, string $verifier): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            $_SESSION['adoaler_pkce_' . $state] = $verifier;
        }
    }

    /**
     * Get verifier from session
     */
    public function getVerifierFromSession(string $state): ?string
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            $key = 'adoaler_pkce_' . $state;
            $verifier = $_SESSION[$key] ?? null;
            unset($_SESSION[$key]);
            return $verifier;
        }
        return null;
    }

    private function postRequest(string $endpoint, array $params): array
    {
        $url = $this->config->baseUrl . $endpoint;

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($params),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->config->timeout,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/x-www-form-urlencoded',
            ],
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200) {
            throw new \Exception("OAuth error: HTTP $httpCode - $response");
        }

        return json_decode($response, true) ?? [];
    }

    private function getRequest(string $endpoint, string $accessToken): array
    {
        $url = $this->config->baseUrl . $endpoint;

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->config->timeout,
            CURLOPT_HTTPHEADER => [
                'Authorization: Bearer ' . $accessToken,
            ],
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200) {
            throw new \Exception("API error: HTTP $httpCode");
        }

        return json_decode($response, true) ?? [];
    }
}
