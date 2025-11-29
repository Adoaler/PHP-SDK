<?php
/**
 * Adoaler Ads SDK for PHP
 * 
 * @package Adoaler\Ads
 * @version 2.0.0
 */

namespace Adoaler;

class AdConfig
{
    public string $publisherId;
    public string $apiKey;
    public string $secretKey;
    public string $baseUrl;
    public int $timeout;

    public function __construct(
        string $publisherId,
        string $apiKey,
        string $secretKey,
        string $baseUrl = 'https://ads.adoaler.com/v1',
        int $timeout = 10
    ) {
        $this->publisherId = $publisherId;
        $this->apiKey = $apiKey;
        $this->secretKey = $secretKey;
        $this->baseUrl = $baseUrl;
        $this->timeout = $timeout;
    }
}

class AdUnit
{
    public string $unitId;
    public string $type;
    public ?string $size;
    public ?string $placementId;
    public array $keywords;
    public array $metadata;

    public function __construct(
        string $unitId,
        string $type,
        ?string $size = null,
        ?string $placementId = null,
        array $keywords = [],
        array $metadata = []
    ) {
        $this->unitId = $unitId;
        $this->type = $type;
        $this->size = $size;
        $this->placementId = $placementId;
        $this->keywords = $keywords;
        $this->metadata = $metadata;
    }
}

class AdResponse
{
    public string $adId;
    public string $type;
    public ?string $html;
    public ?string $imageUrl;
    public ?string $videoUrl;
    public string $clickUrl;
    public string $trackingUrl;
    public ?string $title;
    public ?string $description;
    public ?string $cta;
    public array $metadata;

    public function __construct(array $data)
    {
        $this->adId = $data['ad_id'] ?? '';
        $this->type = $data['type'] ?? '';
        $this->html = $data['html'] ?? null;
        $this->imageUrl = $data['image_url'] ?? null;
        $this->videoUrl = $data['video_url'] ?? null;
        $this->clickUrl = $data['click_url'] ?? '';
        $this->trackingUrl = $data['tracking_url'] ?? '';
        $this->title = $data['title'] ?? null;
        $this->description = $data['description'] ?? null;
        $this->cta = $data['cta'] ?? null;
        $this->metadata = $data['metadata'] ?? [];
    }
}

class AdoalerAds
{
    private AdConfig $config;

    // Ad Types
    public const TYPE_BANNER = 'banner';
    public const TYPE_NATIVE = 'native';
    public const TYPE_INTERSTITIAL = 'interstitial';
    public const TYPE_VIDEO = 'video';
    public const TYPE_REWARDED = 'rewarded';

    // Banner Sizes
    public const SIZE_320x50 = '320x50';
    public const SIZE_300x250 = '300x250';
    public const SIZE_728x90 = '728x90';
    public const SIZE_160x600 = '160x600';
    public const SIZE_300x600 = '300x600';

    public function __construct(AdConfig $config)
    {
        $this->config = $config;
    }

    /**
     * Request an ad
     */
    public function requestAd(AdUnit $unit, array $userContext = []): AdResponse
    {
        $payload = [
            'publisher_id' => $this->config->publisherId,
            'unit_id' => $unit->unitId,
            'type' => $unit->type,
            'timestamp' => time(),
        ];

        if ($unit->size) {
            $payload['size'] = $unit->size;
        }
        if ($unit->placementId) {
            $payload['placement_id'] = $unit->placementId;
        }
        if (!empty($unit->keywords)) {
            $payload['keywords'] = $unit->keywords;
        }
        if (!empty($userContext)) {
            $payload['user_context'] = $userContext;
        }

        $response = $this->sendRequest('/ads/request', $payload);
        return new AdResponse($response);
    }

    /**
     * Track ad impression
     */
    public function trackImpression(string $adId): bool
    {
        return $this->sendTrackingEvent('/ads/impression', $adId, 'impression');
    }

    /**
     * Track ad click
     */
    public function trackClick(string $adId): bool
    {
        return $this->sendTrackingEvent('/ads/click', $adId, 'click');
    }

    /**
     * Track video event
     */
    public function trackVideoEvent(string $adId, string $event, int $position): bool
    {
        $payload = [
            'ad_id' => $adId,
            'event' => $event,
            'position' => $position,
            'publisher_id' => $this->config->publisherId,
            'timestamp' => time(),
        ];

        try {
            $this->sendRequest('/ads/video/event', $payload);
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Track viewability
     */
    public function trackViewability(string $adId, int $viewablePercent, int $duration): bool
    {
        $payload = [
            'ad_id' => $adId,
            'viewable_percent' => $viewablePercent,
            'duration' => $duration,
            'publisher_id' => $this->config->publisherId,
            'timestamp' => time(),
        ];

        try {
            $this->sendRequest('/ads/viewability', $payload);
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Verify webhook callback signature
     */
    public function verifyCallback(string $payload, string $signature): bool
    {
        $expectedSig = $this->signRequest($payload);
        return hash_equals($expectedSig, $signature);
    }

    /**
     * Generate ad tag for web embedding
     */
    public function generateAdTag(AdUnit $unit): string
    {
        $params = http_build_query([
            'pub' => $this->config->publisherId,
            'unit' => $unit->unitId,
            'type' => $unit->type,
            'size' => $unit->size,
        ]);

        return sprintf(
            '<script src="%s/tag.js?%s" async></script>',
            $this->config->baseUrl,
            $params
        );
    }

    private function sendTrackingEvent(string $endpoint, string $adId, string $eventType): bool
    {
        $payload = [
            'ad_id' => $adId,
            'event' => $eventType,
            'publisher_id' => $this->config->publisherId,
            'timestamp' => time(),
        ];

        try {
            $this->sendRequest($endpoint, $payload);
            return true;
        } catch (\Exception $e) {
            return false;
        }
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
