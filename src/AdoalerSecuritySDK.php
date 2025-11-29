<?php
/**
 * Adoaler Security SDK for PHP
 * Server-side integration
 */

namespace Adoaler\Security;

class AdoalerSecuritySDK
{
    private string $apiKey;
    private string $baseUrl;
    private string $sessionId;
    
    public function __construct(string $apiKey, string $baseUrl)
    {
        $this->apiKey = $apiKey;
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->sessionId = bin2hex(random_bytes(16));
    }
    
    /**
     * Verify request from client SDK
     */
    public function verifyRequest(array $headers, string $body): VerificationResult
    {
        $signature = $headers['X-Request-Signature'] ?? '';
        $timestamp = (int) ($headers['X-Request-Timestamp'] ?? 0);
        $nonce = $headers['X-Request-Nonce'] ?? '';
        
        // Verify timestamp (5 minute window)
        if (abs(time() * 1000 - $timestamp) > 300000) {
            return new VerificationResult(false, 0, 'expired', ['Timestamp expired']);
        }
        
        // Verify signature
        $expectedSignature = $this->generateSignature($body, $timestamp, $nonce);
        if (!hash_equals($expectedSignature, $signature)) {
            return new VerificationResult(false, 0, 'invalid', ['Invalid signature']);
        }
        
        // Check nonce (prevent replay)
        if ($this->isNonceUsed($nonce)) {
            return new VerificationResult(false, 0, 'replay', ['Replay detected']);
        }
        
        $this->markNonceUsed($nonce);
        
        return new VerificationResult(true, 100, 'verified', []);
    }
    
    /**
     * Get IP intelligence
     */
    public function getIPIntelligence(string $ip): array
    {
        return $this->request('/api/security/ip-intel', ['ip' => $ip]);
    }
    
    /**
     * Get user risk score
     */
    public function getUserRisk(string $userId): array
    {
        return $this->request("/api/security/user/{$userId}/risk", []);
    }
    
    /**
     * Report security event
     */
    public function reportEvent(string $type, array $data): bool
    {
        $response = $this->request('/api/security/report', [
            'type' => $type,
            'data' => $data,
            'timestamp' => time()
        ]);
        
        return $response['success'] ?? false;
    }
    
    /**
     * Block IP
     */
    public function blockIP(string $ip, string $reason, int $duration = 86400): bool
    {
        $response = $this->request('/api/security/block-ip', [
            'ip' => $ip,
            'reason' => $reason,
            'duration' => $duration
        ]);
        
        return $response['success'] ?? false;
    }
    
    /**
     * Whitelist IP
     */
    public function whitelistIP(string $ip, string $reason): bool
    {
        $response = $this->request('/api/security/whitelist-ip', [
            'ip' => $ip,
            'reason' => $reason
        ]);
        
        return $response['success'] ?? false;
    }
    
    /**
     * Validate device fingerprint
     */
    public function validateFingerprint(array $fingerprint): FingerprintValidation
    {
        $riskFactors = [];
        $score = 100;
        
        // Check for emulator
        if ($fingerprint['is_emulator'] ?? false) {
            $riskFactors[] = 'Emulator detected';
            $score -= 30;
        }
        
        // Check for root/jailbreak
        if ($fingerprint['is_rooted'] ?? false) {
            $riskFactors[] = 'Rooted device';
            $score -= 20;
        }
        
        // Check for suspicious values
        if (empty($fingerprint['device_id'])) {
            $riskFactors[] = 'Missing device ID';
            $score -= 25;
        }
        
        // Check sensor count (real devices have many)
        $sensorCount = $fingerprint['sensors_count'] ?? 0;
        if ($sensorCount < 5) {
            $riskFactors[] = 'Low sensor count';
            $score -= 15;
        }
        
        return new FingerprintValidation(
            max(0, $score),
            $riskFactors,
            $score >= 50
        );
    }
    
    /**
     * Validate behavioral signals
     */
    public function validateBehavioral(array $signals): BehavioralValidation
    {
        $isBot = false;
        $confidence = 0;
        $reasons = [];
        
        // No touch/mouse events
        if (($signals['touch_count'] ?? 0) === 0 && ($signals['mouseMovements'] ?? 0) === 0) {
            $isBot = true;
            $confidence += 0.4;
            $reasons[] = 'No input events';
        }
        
        // Perfect timing (bots often have consistent intervals)
        $keystrokeInterval = $signals['avg_keystroke_interval'] ?? $signals['avgKeystrokeInterval'] ?? 0;
        if ($keystrokeInterval > 0) {
            $variance = $signals['keystroke_variance'] ?? 0;
            if ($variance < 5) { // Too consistent
                $confidence += 0.3;
                $reasons[] = 'Suspicious keystroke pattern';
            }
        }
        
        // No accelerometer on mobile
        if (!($signals['has_accelerometer'] ?? $signals['hasAccelerometerData'] ?? true)) {
            $confidence += 0.2;
            $reasons[] = 'No accelerometer data';
        }
        
        $isBot = $confidence > 0.5;
        
        return new BehavioralValidation($isBot, $confidence, $reasons);
    }
    
    private function request(string $endpoint, array $data): array
    {
        $nonce = bin2hex(random_bytes(16));
        $timestamp = time() * 1000;
        
        $payload = json_encode(array_merge($data, [
            'nonce' => $nonce,
            'timestamp' => $timestamp
        ]));
        
        $signature = $this->generateSignature($payload, $timestamp, $nonce);
        
        $ch = curl_init($this->baseUrl . $endpoint);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $payload,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'X-API-Key: ' . $this->apiKey,
                'X-Request-Signature: ' . $signature,
                'X-Request-Timestamp: ' . $timestamp,
                'X-Request-Nonce: ' . $nonce
            ]
        ]);
        
        $response = curl_exec($ch);
        curl_close($ch);
        
        return json_decode($response, true) ?? [];
    }
    
    private function generateSignature(string $payload, int $timestamp, string $nonce): string
    {
        $data = $payload . $timestamp . $nonce . $this->apiKey;
        return hash_hmac('sha256', $data, $this->apiKey);
    }
    
    private function isNonceUsed(string $nonce): bool
    {
        // Implement with Redis/cache
        return false;
    }
    
    private function markNonceUsed(string $nonce): void
    {
        // Implement with Redis/cache
    }
}

class VerificationResult
{
    public function __construct(
        public bool $verified,
        public int $trustScore,
        public string $status,
        public array $issues
    ) {}
}

class FingerprintValidation
{
    public function __construct(
        public int $score,
        public array $riskFactors,
        public bool $valid
    ) {}
}

class BehavioralValidation
{
    public function __construct(
        public bool $isBot,
        public float $confidence,
        public array $reasons
    ) {}
}
