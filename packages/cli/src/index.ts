#!/usr/bin/env node
import { runEndpointAudit, runSimulateSuite } from './commands/audit';
import { runInitCommand } from './commands/init';

export { runInitCommand } from './commands/init';
export { runSimulateSuite, runEndpointAudit } from './commands/audit';

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const command = (args[0] ?? 'simulate').toLowerCase();

  switch (command) {
    case 'init':
    case 'keys': {
      runInitCommand(process.cwd());
      break;
    }
    case 'simulate':
    case 'test': {
      const result = await runSimulateSuite(false);
      if (!result.allPassed) {
        process.exitCode = 1;
      }
      break;
    }
    case 'audit': {
      const targetUrl = args[1] ?? 'http://localhost:3000';
      await runEndpointAudit(targetUrl);
      break;
    }
    default: {
      console.log(`
NullFilter / OriginLock CLI (v1.0.0)

Usage:
  npx originlock init              Generate RSA-2048 keypair & .env.originlock config
  npx originlock simulate          Run the 4-stage cryptographic & AiTM defense self-test
  npx originlock audit [url]       Inspect a target URL for polymorphic DOM attestation
`);
      break;
    }
  }
}

if (require.main === module) {
  void main();
}
