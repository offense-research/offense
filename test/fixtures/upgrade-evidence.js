export function passingUpgradeEvidence({ changes = [{ name:'example',currentVersion:'1.0.0',targetVersion:'1.0.1' }], revision='a'.repeat(40) } = {}) {
  const command = (directory, argv) => ({directory,command:argv,exitCode:0,passed:true,timedOut:false,truncated:false,signal:null});
  const install=['npm','ci','--ignore-scripts'], checks=['npm','run','--ignore-scripts','test'];
  const baseline={integrity:true,integrityVersion:2,setup:[command('source',install)],checks:[command('source',checks)]};
  const scenario={status:'tests_passed',changes,integrity:true,integrityVersion:2,resolution:[command('candidate-0',['npm','install','--package-lock-only','--ignore-scripts'])],
    setup:[command('candidate-0',install)],checks:[command('candidate-0',checks)],coverage:changes.map(change=>({...change,targetPresent:true,oldVersionRemaining:false})),
    remainingAdvisories:0,vulnerabilityCheck:{status:'complete',checkedPackages:1,skippedPackages:0,findings:[]},newAdvisories:[],unrehearsedFindings:[]};
  return {status:'completed',revision,result:{status:'completed',revision,baseline,scenarios:[scenario]}};
}
