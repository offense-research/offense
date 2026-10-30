import { DurableObject } from 'cloudflare:workers';
import { assessmentEgressRequest, createAssessmentEgressController } from './assessment-egress-controller.js';

export class AssessmentEgressGateway extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.gateway = createAssessmentEgressController(ctx, env);
  }
  fetch(request) { return this.gateway.fetch(request); }
  status() { return this.gateway.status(); }
}

export default { fetch: assessmentEgressRequest };
