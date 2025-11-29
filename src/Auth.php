<?php
/**
 * Adoaler Auth SDK for PHP - Authentication & Session Management
 * 
 * @package Adoaler\Auth
 * @version 2.0.0
 */

namespace Adoaler;

class AuthConfig
{
    public string $apiKey;
    public string $secretKey;
    public string $baseUrl;
    public int $sessionTTL;
    public bool $enableMFA;
    public int $timeout;

    public function __construct(
        string $apiKey,
        string $secretKey,
        string $baseUrl = 'https://auth.adoaler.com/v1',
        int $sessionTTL = 86400,
        bool $enableMFA = false,
        int $timeout = 30
    ) {
        $this->apiKey = $apiKey;
        $this->secretKey = $secretKey;
        $this->baseUrl = $baseUrl;
        $this->sessionTTL = $sessionTTL;
        $this->enableMFA = $enableMFA;
        $this->timeout = $timeout;
    }
}

class Session
{
    public string $id;
    public string $userId;
    public int $createdAt;
    public int $expiresAt;
    public ?string $ipAddress;
    public ?string $userAgent;
    public ?string $deviceId;
    public array $metadata;
    public bool $isActive;

    public function __construct(array $data)
    {
        $this->id = $data['session_id'] ?? '';
        $this->userId = $data['user_id'] ?? '';
        $this->createdAt = $data['created_at'] ?? time();
        $this->expiresAt = $data['expires_at'] ?? (time() + 86400);
        $this->ipAddress = $data['ip_address'] ?? null;
        $this->userAgent = $data['user_agent'] ?? null;
        $this->deviceId = $data['device_id'] ?? null;
        $this->metadata = $data['metadata'] ?? [];
        $this->isActive = $data['is_active'] ?? true;
    }

    public function isExpired(): bool
    {
        return time() > $this->expiresAt;
    }
}

class MFASetup
{
    public string $method;
    public ?string $secret;
    public ?string $qrCodeUrl;
    public array $backupCodes;

    public function __construct(array $data)
    {
        $this->method = $data['method'] ?? '';
        $this->secret = $data['secret'] ?? null;
        $this->qrCodeUrl = $data['qr_code_url'] ?? null;
        $this->backupCodes = $data['backup_codes'] ?? [];
    }
}

class AdoalerAuth
{
    private AuthConfig $config;
    private array $sessions = [];

    public const MFA_TOTP = 'totp';
    public const MFA_SMS = 'sms';
    public const MFA_EMAIL = 'email';

    public function __construct(AuthConfig $config)
    {
        $this->config = $config;
    }

    /**
     * Login user
     */
    public function login(string $email, string $password, array $metadata = []): Session
    {
        $payload = [
            'email' => $email,
            'password' => $password,
        ];

        if (!empty($metadata)) {
            $payload['metadata'] = $metadata;
        }

        $response = $this->sendRequest('/auth/login', $payload);
        $session = new Session($response);
        $this->sessions[$session->id] = $session;

        return $session;
    }

    /**
     * Logout user
     */
    public function logout(string $sessionId): bool
    {
        try {
            $this->sendRequest('/auth/logout', ['session_id' => $sessionId]);
            unset($this->sessions[$sessionId]);
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Validate session
     */
    public function validateSession(string $sessionId): ?Session
    {
        try {
            $response = $this->sendRequest('/auth/session/validate', [
                'session_id' => $sessionId,
            ]);
            return new Session($response);
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Refresh session
     */
    public function refreshSession(string $sessionId): ?Session
    {
        try {
            $response = $this->sendRequest('/auth/session/refresh', [
                'session_id' => $sessionId,
            ]);
            $session = new Session($response);
            $this->sessions[$session->id] = $session;
            return $session;
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Setup MFA
     */
    public function setupMFA(string $userId, string $method): MFASetup
    {
        $response = $this->sendRequest('/auth/mfa/setup', [
            'user_id' => $userId,
            'method' => $method,
        ]);

        return new MFASetup($response);
    }

    /**
     * Verify MFA code
     */
    public function verifyMFA(string $userId, string $code): bool
    {
        try {
            $this->sendRequest('/auth/mfa/verify', [
                'user_id' => $userId,
                'code' => $code,
            ]);
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Send MFA code
     */
    public function sendMFACode(string $userId, string $method): bool
    {
        try {
            $this->sendRequest('/auth/mfa/send', [
                'user_id' => $userId,
                'method' => $method,
            ]);
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Hash password
     */
    public static function hashPassword(string $password): string
    {
        return password_hash($password, PASSWORD_ARGON2ID);
    }

    /**
     * Verify password
     */
    public static function verifyPassword(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * Generate session ID
     */
    public static function generateSessionId(): string
    {
        return bin2hex(random_bytes(32));
    }

    /**
     * PSR-15 style middleware
     */
    public function middleware(callable $next): callable
    {
        return function ($request) use ($next) {
            $sessionId = $request->getHeaderLine('X-Session-ID');
            
            if (empty($sessionId) && isset($_COOKIE['adoaler_session'])) {
                $sessionId = $_COOKIE['adoaler_session'];
            }

            if (empty($sessionId)) {
                http_response_code(401);
                return ['error' => 'Unauthorized'];
            }

            $session = $this->validateSession($sessionId);
            if (!$session) {
                http_response_code(401);
                return ['error' => 'Invalid session'];
            }

            $request = $request->withAttribute('user_id', $session->userId);
            $request = $request->withAttribute('session', $session);

            return $next($request);
        };
    }

    /**
     * Set session cookie
     */
    public function setSessionCookie(Session $session, bool $secure = true): void
    {
        setcookie('adoaler_session', $session->id, [
            'expires' => $session->expiresAt,
            'path' => '/',
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    /**
     * Clear session cookie
     */
    public function clearSessionCookie(): void
    {
        setcookie('adoaler_session', '', [
            'expires' => time() - 3600,
            'path' => '/',
        ]);
    }

    private function sendRequest(string $endpoint, array $payload): array
    {
        $url = $this->config->baseUrl . $endpoint;
        $jsonPayload = json_encode($payload);
        $signature = $this->signRequest($jsonPayload);

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $jsonPayload,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->config->timeout,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'X-Adoaler-Key: ' . $this->config->apiKey,
                'X-Adoaler-Signature: ' . $signature,
            ],
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode === 401) {
            throw new \Exception('Invalid credentials');
        }

        if ($httpCode !== 200) {
            throw new \Exception("API error: HTTP $httpCode");
        }

        return json_decode($response, true) ?? [];
    }

    private function signRequest(string $data): string
    {
        return hash_hmac('sha256', $data, $this->config->secretKey);
    }
}
