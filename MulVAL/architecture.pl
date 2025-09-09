/* Attack goal */
attackGoal(canPrivEsc(controlFlow4)).
attackGoal(canDoS(controlFlow1)).

/* Attacker location */
attackerLocated(logicalAdversary).
attackerPrivilege(directAttacks).

/* Vuln */
weaknessExist(interruptDispacter, cwe20).
weaknessExist(interruptDispacter, cwe754).
weaknessExist(securityContext, cwe119).

/* Control flows */
controlFlow(runtimeEnviroment, interruptDispacter, controlFlow1).
controlFlow(domainSecurityManager, interruptDispacter, controlFlow5).
controlFlow(interruptDispacter, securityContext, controlFlow3).
controlFlow(interruptDispacter, securityContext, controlFlow6).
controlFlow(securityContext, pmp, controlFlow4).
controlFlow(securityContext, pmp, controlFlow7).

feedbackFlow(interruptDispacter, runtimeEnviroment, feedbackFlow3).
feedbackFlow(interruptDispacter, domainSecurityManager, feedbackFlow2).
feedbackFlow(domainManager, interruptDispacter, feedbackFlow1).
