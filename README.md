# Adoaler PHP SDK

[![Latest Version on Packagist](https://img.shields.io/packagist/v/adoaler/sdk.svg)](https://packagist.org/packages/adoaler/sdk)
[![PHP Version](https://img.shields.io/packagist/php-v/adoaler/sdk.svg)](https://packagist.org/packages/adoaler/sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

SDK oficial PHP para integração com o Adoaler Security Platform.

## Requisitos

- PHP 8.1+
- Composer
- ext-curl
- ext-json
- ext-openssl

## Instalação

```bash
composer require adoaler/sdk
```

## Quick Start

```php
<?php

use Adoaler\Client;

$client = new Client([
    'api_key' => 'sua_api_key',
    'environment' => 'production'
]);

// Verificar IP
$result = $client->ip()->check('203.0.113.42');
echo "Risk Score: " . $result->riskScore . "\n";
echo "Risk Level: " . $result->riskLevel . "\n";

// Verificar fraude em transação
$fraudResult = $client->fraud()->checkTransaction([
    'transaction_id' => 'txn_123',
    'amount' => 199.99,
    'currency' => 'BRL',
    'user_id' => 'user_123',
    'ip' => '203.0.113.42'
]);

if ($fraudResult->recommendation === 'decline') {
    echo "Transação bloqueada";
}
```

## Funcionalidades

### IP Intelligence

```php
// Verificação de IP
$ipInfo = $client->ip()->check('203.0.113.42');

// Propriedades disponíveis
$ipInfo->ip;           // IP verificado
$ipInfo->riskScore;    // Score de risco (0-100)
$ipInfo->riskLevel;    // 'critical' | 'high' | 'medium' | 'low'
$ipInfo->isVpn;        // É VPN?
$ipInfo->isProxy;      // É proxy?
$ipInfo->isTor;        // É Tor?
$ipInfo->isDatacenter; // É datacenter?
$ipInfo->country;      // País (código ISO)
$ipInfo->city;         // Cidade
$ipInfo->asn;          // ASN
$ipInfo->organization; // Organização

// Verificação em lote
$results = $client->ip()->checkBatch([
    '203.0.113.42',
    '198.51.100.23'
]);

foreach ($results as $result) {
    echo "{$result->ip}: {$result->riskLevel}\n";
}

// IP History
$history = $client->ip()->getHistory('203.0.113.42', [
    'start_date' => '2025-11-01',
    'end_date' => '2025-11-29'
]);
```

### Device Fingerprinting

```php
// Verificar fingerprint
$deviceInfo = $client->device()->verify([
    'fingerprint' => 'fp_hash_do_cliente',
    'user_agent' => $_SERVER['HTTP_USER_AGENT'],
    'ip' => $_SERVER['REMOTE_ADDR']
]);

$deviceInfo->isKnown;        // Dispositivo conhecido?
$deviceInfo->trustScore;     // Score de confiança
$deviceInfo->firstSeen;      // Primeira vez visto
$deviceInfo->riskSignals;    // Sinais de risco

// Listar dispositivos de um usuário
$devices = $client->device()->listByUser('user_123');
```

### Bot Detection

```php
$botCheck = $client->bot()->detect([
    'fingerprint' => 'fp_hash',
    'user_agent' => $_SERVER['HTTP_USER_AGENT'],
    'ip' => $_SERVER['REMOTE_ADDR'],
    'behavior' => $behaviorSignals // Coletado no client-side
]);

$botCheck->isBot;        // boolean
$botCheck->botType;      // 'crawler' | 'scraper' | 'automation' | null
$botCheck->confidence;   // 0-1
$botCheck->humanScore;   // 0-100
$botCheck->signals;      // Sinais detectados
```

### Fraud Detection

```php
$fraudCheck = $client->fraud()->checkTransaction([
    'transaction_id' => 'txn_123',
    'amount' => 199.99,
    'currency' => 'BRL',
    'user_id' => 'user_123',
    'device_fingerprint' => 'fp_hash',
    'ip' => '203.0.113.42',
    'email' => 'user@example.com',
    'metadata' => [
        'product_category' => 'electronics',
        'payment_method' => 'credit_card'
    ]
]);

$fraudCheck->riskScore;       // 0-100
$fraudCheck->riskLevel;       // 'critical' | 'high' | 'medium' | 'low'
$fraudCheck->recommendation;  // 'approve' | 'review' | 'decline'
$fraudCheck->signals;         // Sinais de risco
$fraudCheck->rulesTriggered;  // Regras acionadas

// Reportar fraude confirmada (feedback)
$client->fraud()->report([
    'transaction_id' => 'txn_123',
    'is_fraud' => true,
    'fraud_type' => 'account_takeover'
]);
```

### User Risk

```php
$userRisk = $client->user()->getRisk('user_123');

$userRisk->riskScore;      // Score de risco
$userRisk->trustScore;     // Score de confiança
$userRisk->riskFactors;    // Fatores de risco
$userRisk->deviceCount;    // Número de dispositivos
$userRisk->anomalies;      // Anomalias detectadas

// Listar eventos do usuário
$events = $client->user()->getEvents('user_123', [
    'limit' => 100,
    'event_types' => ['login', 'transaction']
]);
```

### Events

```php
// Registrar evento
$client->events()->track([
    'event_type' => 'login',
    'user_id' => 'user_123',
    'ip' => '203.0.113.42',
    'device_fingerprint' => 'fp_hash',
    'metadata' => [
        'method' => 'password',
        'success' => true
    ]
]);

// Buscar eventos
$events = $client->events()->search([
    'start_date' => '2025-11-01',
    'end_date' => '2025-11-29',
    'event_types' => ['login', 'transaction'],
    'risk_level' => 'high',
    'limit' => 100
]);
```

## Integração com Frameworks

### Laravel

```php
// config/services.php
'adoaler' => [
    'api_key' => env('ADOALER_API_KEY'),
    'environment' => env('ADOALER_ENVIRONMENT', 'production'),
],

// app/Providers/AppServiceProvider.php
use Adoaler\Client;

public function register()
{
    $this->app->singleton(Client::class, function ($app) {
        return new Client([
            'api_key' => config('services.adoaler.api_key'),
            'environment' => config('services.adoaler.environment'),
        ]);
    });
}

// Uso em Controller
use Adoaler\Client;

class PaymentController extends Controller
{
    public function __construct(private Client $adoaler) {}
    
    public function checkout(Request $request)
    {
        $fraudCheck = $this->adoaler->fraud()->checkTransaction([
            'transaction_id' => $request->transaction_id,
            'amount' => $request->amount,
            'user_id' => $request->user()->id,
            'ip' => $request->ip(),
        ]);
        
        if ($fraudCheck->recommendation === 'decline') {
            return response()->json(['error' => 'Transação bloqueada'], 403);
        }
        
        // Processar pagamento...
    }
}
```

### Laravel Middleware

```php
// app/Http/Middleware/AdoalerSecurity.php
namespace App\Http\Middleware;

use Adoaler\Client;
use Closure;
use Illuminate\Http\Request;

class AdoalerSecurity
{
    public function __construct(private Client $adoaler) {}
    
    public function handle(Request $request, Closure $next)
    {
        $ipCheck = $this->adoaler->ip()->check($request->ip());
        
        if ($ipCheck->riskLevel === 'critical') {
            return response()->json(['error' => 'Access denied'], 403);
        }
        
        $request->merge(['adoaler' => $ipCheck]);
        
        return $next($request);
    }
}

// app/Http/Kernel.php
protected $middlewareAliases = [
    'adoaler' => \App\Http\Middleware\AdoalerSecurity::class,
];

// Uso em rotas
Route::middleware('adoaler')->group(function () {
    Route::post('/checkout', [PaymentController::class, 'checkout']);
});
```

### Symfony

```php
// config/services.yaml
services:
    Adoaler\Client:
        arguments:
            - api_key: '%env(ADOALER_API_KEY)%'
              environment: '%env(ADOALER_ENVIRONMENT)%'

// src/Controller/PaymentController.php
use Adoaler\Client;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;

class PaymentController extends AbstractController
{
    public function checkout(Request $request, Client $adoaler): JsonResponse
    {
        $fraudCheck = $adoaler->fraud()->checkTransaction([
            'transaction_id' => $request->get('transaction_id'),
            'amount' => $request->get('amount'),
            'user_id' => $this->getUser()->getId(),
            'ip' => $request->getClientIp(),
        ]);
        
        if ($fraudCheck->recommendation === 'decline') {
            return new JsonResponse(['error' => 'Blocked'], 403);
        }
        
        // Processar...
        return new JsonResponse(['status' => 'ok']);
    }
}
```

### Symfony Security Listener

```php
// src/EventListener/AdoalerSecurityListener.php
namespace App\EventListener;

use Adoaler\Client;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

class AdoalerSecurityListener
{
    public function __construct(private Client $adoaler) {}
    
    public function onKernelRequest(RequestEvent $event): void
    {
        $request = $event->getRequest();
        $ipCheck = $this->adoaler->ip()->check($request->getClientIp());
        
        if ($ipCheck->riskLevel === 'critical') {
            throw new AccessDeniedHttpException('Access denied');
        }
        
        $request->attributes->set('adoaler', $ipCheck);
    }
}
```

## Webhooks

```php
use Adoaler\Webhook\Handler;
use Adoaler\Webhook\Event;

$handler = new Handler([
    'signing_secret' => 'seu_webhook_secret'
]);

// Verificar assinatura e processar
$payload = file_get_contents('php://input');
$signature = $_SERVER['HTTP_X_ADOALER_SIGNATURE'] ?? '';

try {
    $event = $handler->verifyAndParse($payload, $signature);
    
    switch ($event->type) {
        case 'threat.detected':
            handleThreat($event->data);
            break;
        case 'device.suspicious':
            handleSuspiciousDevice($event->data);
            break;
    }
    
    http_response_code(200);
    echo json_encode(['received' => true]);
} catch (\Adoaler\Exceptions\InvalidSignatureException $e) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid signature']);
}
```

### Laravel Webhook Controller

```php
// app/Http/Controllers/WebhookController.php
namespace App\Http\Controllers;

use Adoaler\Webhook\Handler;
use Illuminate\Http\Request;

class WebhookController extends Controller
{
    public function handle(Request $request, Handler $handler)
    {
        try {
            $event = $handler->verifyAndParse(
                $request->getContent(),
                $request->header('x-adoaler-signature')
            );
            
            match ($event->type) {
                'threat.detected' => $this->handleThreat($event->data),
                'device.suspicious' => $this->handleSuspiciousDevice($event->data),
                default => null
            };
            
            return response()->json(['received' => true]);
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 400);
        }
    }
}
```

## Tratamento de Erros

```php
use Adoaler\Exceptions\AdoalerException;
use Adoaler\Exceptions\AuthenticationException;
use Adoaler\Exceptions\RateLimitException;
use Adoaler\Exceptions\ValidationException;
use Adoaler\Exceptions\NetworkException;

try {
    $result = $client->ip()->check('203.0.113.42');
} catch (RateLimitException $e) {
    echo "Rate limit excedido. Retry após: {$e->getRetryAfter()}s\n";
} catch (AuthenticationException $e) {
    echo "Chave de API inválida\n";
} catch (ValidationException $e) {
    echo "Dados inválidos:\n";
    foreach ($e->getErrors() as $field => $messages) {
        echo "  - {$field}: " . implode(', ', $messages) . "\n";
    }
} catch (NetworkException $e) {
    echo "Erro de rede: {$e->getMessage()}\n";
} catch (AdoalerException $e) {
    echo "Erro: {$e->getMessage()}\n";
}
```

## Configuração Avançada

```php
$client = new Client([
    'api_key' => 'sua_api_key',
    'environment' => 'production',   // 'production' | 'sandbox'
    'timeout' => 30,                 // timeout em segundos
    'max_retries' => 3,              // tentativas em caso de falha
    'retry_delay' => 1,              // delay entre tentativas (s)
    'debug' => false,                // modo debug
    'base_url' => null,              // URL customizada (para self-hosted)
    'verify_ssl' => true,            // verificar SSL
]);

// HTTP Client customizado (PSR-18)
use GuzzleHttp\Client as GuzzleClient;

$httpClient = new GuzzleClient([
    'proxy' => 'http://proxy.example.com:8080'
]);

$client = new Client([
    'api_key' => 'sua_api_key',
    'http_client' => $httpClient
]);
```

## Cache

```php
// PSR-16 Simple Cache
use Symfony\Component\Cache\Psr16Cache;
use Symfony\Component\Cache\Adapter\RedisAdapter;

$redis = RedisAdapter::createConnection('redis://localhost');
$cache = new Psr16Cache(new RedisAdapter($redis));

$client = new Client([
    'api_key' => 'sua_api_key',
    'cache' => $cache,
    'cache_ttl' => 300 // 5 minutos
]);

// Com Laravel
$client = new Client([
    'api_key' => config('services.adoaler.api_key'),
    'cache' => app('cache.store')
]);
```

## Logging

```php
// PSR-3 Logger
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

$logger = new Logger('adoaler');
$logger->pushHandler(new StreamHandler('path/to/adoaler.log', Logger::DEBUG));

$client = new Client([
    'api_key' => 'sua_api_key',
    'logger' => $logger,
    'log_level' => 'debug' // 'debug', 'info', 'warning', 'error'
]);
```

## Testes

```php
// Usar ambiente sandbox
$client = new Client([
    'api_key' => 'sua_api_key',
    'environment' => 'sandbox'
]);

// Mock para testes unitários
use Adoaler\Testing\MockClient;

$mockClient = MockClient::create()
    ->mockIpCheck('203.0.113.42', [
        'risk_score' => 85,
        'risk_level' => 'high',
        'is_vpn' => true
    ])
    ->mockFraudCheck([
        'recommendation' => 'decline'
    ]);

// Usar em testes
$result = $mockClient->ip()->check('203.0.113.42');
$this->assertEquals('high', $result->riskLevel);
```

## Documentação

- **Docs**: https://docs.adoaler.com/sdk/php
- **API Reference**: https://docs.adoaler.com/api
- **Examples**: https://github.com/adoaler/php-sdk/examples

## Suporte

- **Email**: support@adoaler.com
- **GitHub Issues**: https://github.com/adoaler/php-sdk/issues
- **Discord**: https://discord.gg/adoaler

## Licença

MIT License - veja [LICENSE](LICENSE) para detalhes.
