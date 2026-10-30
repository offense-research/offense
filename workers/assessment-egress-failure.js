export const ASSESSMENT_FAILURE_REASONS = Object.freeze([
  'unknown', 'request_cancelled', 'response_cancelled', 'request_stream_error', 'response_stream_error',
  'connection_deadline', 'byte_budget', 'websocket_error', 'websocket_closed', 'websocket_protocol',
  'websocket_write', 'socket_open', 'socket_upload', 'socket_headers', 'socket_framing',
  'gateway_unavailable', 'destination_denied', 'scope_denied', 'upstream_denied'
]);
export const assessmentFailureReason = value => ASSESSMENT_FAILURE_REASONS.includes(value) ? value : 'unknown';
