import type { CallbackManagerForChainRun } from '@langchain/core/callbacks/manager';
import { HumanMessage } from '@langchain/core/messages';
import type { BasePromptValueInterface } from '@langchain/core/prompt_values';
import { Runnable, type RunnableConfig } from '@langchain/core/runnables';
import { IPIntelService, PangeaConfig } from 'pangea-node-sdk';

export class MaliciousIpAddressesError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MaliciousIpAddressesError';
  }
}

const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;

export class PangeaIpIntelGuard<
  RunInput extends BasePromptValueInterface,
> extends Runnable<RunInput, RunInput> {
  static lc_name() {
    return 'PangeaIpIntelGuard';
  }

  lc_namespace = ['pangeacyber', 'runnables'];

  private client;
  private threshold: number;

  constructor(token: string, domain = 'aws.us.pangea.cloud', threshold = 70) {
    super();
    this.client = new IPIntelService(token, new PangeaConfig({ domain }));
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

    // Find all IP addresses in the text.
    const ipAddresses = text.match(IP_RE);
    if (!ipAddresses?.length) {
      return input;
    }

    // Check the reputation of each IP address.
    const intel = await this.client.reputationBulk(ipAddresses);
    if (!intel.result) {
      throw new Error('Failed to retrieve reputation data.');
    }
    if (
      Object.values(intel.result.data).some(
        ({ score }) => score >= this.threshold
      )
    ) {
      throw new MaliciousIpAddressesError(
        'One or more IP addresses have a malice score above the threshold.'
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
