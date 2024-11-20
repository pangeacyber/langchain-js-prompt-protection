import process from 'node:process';

import { config } from '@dotenvx/dotenvx';
import { StringOutputParser } from '@langchain/core/output_parsers';
import {
  ChatPromptTemplate,
  HumanMessagePromptTemplate,
} from '@langchain/core/prompts';
import { RunnableSequence } from '@langchain/core/runnables';
import { ChatOpenAI } from '@langchain/openai';
import { defineCommand, runMain } from 'citty';
import { consola } from 'consola';

import { PangeaAuditRunnable } from './runnables/audit.js';
import {
  MaliciousDomainsError,
  PangeaDomainIntelGuard,
} from './runnables/domain-intel.js';
import {
  MaliciousIpAddressesError,
  PangeaIpIntelGuard,
} from './runnables/ip-intel.js';
import { PangeaRedactRunnable } from './runnables/redact.js';
import {
  MaliciousUrlsError,
  PangeaUrlIntelGuard,
} from './runnables/url-intel.js';

config({ override: true, quiet: true });

const main = defineCommand({
  args: {
    prompt: { type: 'positional' },
    auditConfigId: {
      type: 'string',
      description: 'Pangea Secure Audit Log configuration ID.',
    },
    model: {
      type: 'string',
      default: 'gpt-4o-mini',
      description: 'OpenAI model.',
    },
  },
  async run({ args }) {
    const auditToken = process.env.PANGEA_AUDIT_TOKEN;
    if (!auditToken) {
      consola.warn('PANGEA_AUDIT_TOKEN is not set.');
      return;
    }

    const redactToken = process.env.PANGEA_REDACT_TOKEN;
    if (!redactToken) {
      consola.warn('PANGEA_REDACT_TOKEN is not set.');
      return;
    }

    const domainIntelToken = process.env.PANGEA_DOMAIN_INTEL_TOKEN;
    if (!domainIntelToken) {
      consola.warn('PANGEA_DOMAIN_INTEL_TOKEN is not set.');
      return;
    }

    const ipIntelToken = process.env.PANGEA_IP_INTEL_TOKEN;
    if (!ipIntelToken) {
      consola.warn('PANGEA_IP_INTEL_TOKEN is not set.');
      return;
    }

    const urlIntelToken = process.env.PANGEA_URL_INTEL_TOKEN;
    if (!urlIntelToken) {
      consola.warn('PANGEA_URL_INTEL_TOKEN is not set.');
      return;
    }

    const pangeaDomain = process.env.PANGEA_DOMAIN || 'aws.us.pangea.cloud';

    const prompt = ChatPromptTemplate.fromMessages([
      HumanMessagePromptTemplate.fromTemplate('{input}'),
    ]);
    const model = new ChatOpenAI({ model: args.model });
    const chain = RunnableSequence.from([
      prompt,
      new PangeaAuditRunnable(auditToken, args.auditConfigId, pangeaDomain),
      new PangeaRedactRunnable(redactToken, pangeaDomain),
      new PangeaDomainIntelGuard(domainIntelToken, pangeaDomain),
      new PangeaIpIntelGuard(ipIntelToken, pangeaDomain),
      new PangeaUrlIntelGuard(urlIntelToken, pangeaDomain),
      model,
      new StringOutputParser(),
    ]);

    try {
      consola.log(await chain.invoke({ input: args.prompt }));
    } catch (error) {
      if (error instanceof MaliciousDomainsError) {
        consola.error('The prompt contained malicious domains.');
      } else if (error instanceof MaliciousIpAddressesError) {
        consola.error('The prompt contained malicious IP addresses.');
      } else if (error instanceof MaliciousUrlsError) {
        consola.error('The prompt contained malicious URLs.');
      } else {
        throw error;
      }
    }
  },
});

runMain(main);
