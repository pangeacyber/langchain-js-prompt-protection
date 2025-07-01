import type { CallbackManagerForChainRun } from '@langchain/core/callbacks/manager';
import { HumanMessage } from '@langchain/core/messages';
import type { BasePromptValueInterface } from '@langchain/core/prompt_values';
import { Runnable, type RunnableConfig } from '@langchain/core/runnables';
import { DomainIntelService, PangeaConfig } from 'pangea-node-sdk';

export class MaliciousDomainsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MaliciousDomainsError';
  }
}

const DOMAIN_RE = /\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/;

export class PangeaDomainIntelGuard<
  RunInput extends BasePromptValueInterface,
> extends Runnable<RunInput, RunInput> {
  static lc_name() {
    return 'PangeaDomainIntelGuard';
  }

  lc_namespace = ['pangeacyber', 'runnables'];

  private client;
  private threshold: number;

  constructor(token: string, domain = 'aws.us.pangea.cloud', threshold = 70) {
    super();
    this.client = new DomainIntelService(token, new PangeaConfig({ domain }));
    this.threshold = threshold;
  }

  async _invoke(
    input: RunInput,
    _config?: Partial<RunnableConfig>,
    _runManager?: CallbackManagerForChainRun
  ): Promise<RunInput> {
    const messages = input.toChatMessages();
    const humanMessages = messages.filter((m) => m instanceof HumanMessage);
    const text = humanMessages.pop()?.content as string;
    if (!text) {
      return input;
    }

    // Find all domains in the text.
    const domains = text.match(DOMAIN_RE);
    if (!domains?.length) {
      return input;
    }

    // Check the reputation of each domain.
    const intel = await this.client.reputationBulk(domains);
    if (!intel.result) {
      throw new Error('Failed to retrieve reputation data.');
    }
    if (
      Object.values(intel.result.data).some(
        ({ score }) => score >= this.threshold
      )
    ) {
      throw new MaliciousDomainsError(
        'One or more domains have a malice score above the threshold.'
      );
    }

    return input;
  }

  override invoke(
    input: RunInput,
    config: Partial<RunnableConfig> = {}
  ): Promise<RunInput> {
    return this._callWithConfig(this._invoke, input, config);
  }
}
