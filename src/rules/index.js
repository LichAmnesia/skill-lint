import R01 from './R01-prompt-injection.js';
import R02 from './R02-obfuscation.js';
import R03 from './R03-shell-danger.js';
import R04 from './R04-credential-exfil.js';
import R05 from './R05-external-fetch.js';
import R06 from './R06-suspicious-binaries.js';
import R07 from './R07-persistence-tamper.js';
import R08 from './R08-destructive-ops.js';
import R09 from './R09-metadata-abuse.js';
import R10 from './R10-over-privilege.js';

export const ALL_RULES = [R01, R02, R03, R04, R05, R06, R07, R08, R09, R10];
