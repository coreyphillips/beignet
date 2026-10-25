/**
 * The HTTP daemon that serves a `BeignetNode`, with its API keys, webhooks,
 * rate limiter and OpenAPI document. Node only.
 * @module beignet/daemon
 */
export { startDaemon, DaemonOptions, IStartedDaemon } from './cli/daemon';
export {
	ApiKeyAuthenticator,
	ApiKeyDefinition,
	ApiScope,
	AuthResult,
	AuthSuccess,
	ROUTE_SCOPES,
	getRouteScopes,
	scopesAllowRoute
} from './cli/auth';
export { getOpenApiSpec } from './cli/openapi';
export {
	WebhookManager,
	IWebhookStorage,
	WebhookDeliveryOptions,
	WebhookDeliveryStats
} from './cli/webhooks';
export { HttpRateLimiter, RateLimitOptions } from './cli/http-rate-limiter';
