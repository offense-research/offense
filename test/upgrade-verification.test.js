import test from 'node:test';
import assert from 'node:assert/strict';
import { assessUpgradeRehearsal, assessUpgradeScenario, commandPassed } from '../shared/upgrade-verification.js';
import { passingUpgradeEvidence } from './fixtures/upgrade-evidence.js';
test('compatibility gate requires complete baseline, candidate, exact check parity, target coverage and clean final scan',()=>{
  const job=passingUpgradeEvidence(),assessment=assessUpgradeRehearsal(job);assert.equal(assessment.compatibilityPassed,true);assert.equal(assessment.exploitRemediationVerified,false);
  for(const mutate of [j=>delete j.result.baseline.integrity,j=>delete j.result.baseline.integrityVersion,j=>delete j.result.scenarios[0].integrityVersion,j=>j.result.baseline.setup=[],j=>delete j.result.scenarios[0].integrity,
    j=>j.result.scenarios[0].resolution=[],j=>j.result.scenarios[0].setup=[],j=>j.result.scenarios[0].checks=[],j=>j.result.scenarios[0].checks[0].command=['npm','run','build'],
    j=>j.result.scenarios[0].checks[0].directory='candidate-0/other-workspace',j=>j.result.scenarios[0].coverage=[],
    j=>j.result.scenarios[0].coverage[0].oldVersionRemaining=true,j=>delete j.result.scenarios[0].vulnerabilityCheck.findings,
    j=>j.result.scenarios[0].vulnerabilityCheck.findings=[{id:'new'}],j=>j.result.scenarios[0].vulnerabilityCheck.skippedPackages=1,
    j=>delete j.result.scenarios[0].newAdvisories,j=>j.result.scenarios[0].unrehearsedFindings=[{id:'uncovered'}],j=>j.blockers=[{reason:'unplanned package'}],
    j=>j.result.scenarios=[],j=>j.stale=true,j=>j.status='running']){
      const candidate=structuredClone(job);mutate(candidate);const result=assessUpgradeRehearsal(candidate);assert.equal(result.compatibilityPassed,false,mutate.toString());assert.ok(result.blockers.every(blocker=>blocker.nextStep));
  }
});
test('passing booleans never erase crashes, truncation, missing exit status or a conflicting status',()=>{
  const value=passingUpgradeEvidence().result.baseline.checks[0];assert.equal(commandPassed(value),true);
  for(const change of [{passed:'yes'},{exitCode:1},{code:1},{signal:'SIGTERM'},{timedOut:true},{truncated:true},{command:[]},{exitCode:undefined}])assert.equal(commandPassed({...value,...change}),false);
});
test('parity is independent of execution order but preserves workspace and duplicate-check multiplicity',()=>{
  const job=passingUpgradeEvidence(),b=job.result.baseline,s=job.result.scenarios[0];b.checks.push({...b.checks[0],directory:'source/api'});s.checks.unshift({...s.checks[0],directory:'candidate-0/api'});
  assert.equal(assessUpgradeScenario(b,s).compatibilityPassed,true);s.checks[0].directory='candidate-0';assert.equal(assessUpgradeScenario(b,s).compatibilityPassed,false);
});
test('unexecuted, conflicting, duplicate or wrong-version targets cannot borrow another path’s evidence',()=>{
  const job=passingUpgradeEvidence();for(const mutate of [s=>s.changes.push({...s.changes[0]}),s=>s.changes.push({...s.changes[0],targetVersion:'2.0.0'}),s=>s.coverage[0].targetVersion='2.0.0']){
    const candidate=structuredClone(job.result.scenarios[0]);mutate(candidate);assert.equal(assessUpgradeScenario(job.result.baseline,candidate).targetCoveragePassed,false);
  }
});

test('an empty or uncounted final scan cannot establish that proposed installed targets were checked',()=>{
  for(const count of [0,undefined,-1,1.5]){const job=passingUpgradeEvidence();job.result.scenarios[0].vulnerabilityCheck.checkedPackages=count;assert.equal(assessUpgradeRehearsal(job).compatibilityPassed,false);}
});

test('repeated malformed proposed rows remain explicit blockers instead of crashing the report',()=>{
  const job=passingUpgradeEvidence();job.result.scenarios[0].changes=[null,null];assert.equal(assessUpgradeRehearsal(job).compatibilityPassed,false);
});
