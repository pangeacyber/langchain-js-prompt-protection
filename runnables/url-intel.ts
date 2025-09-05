import type { CallbackManagerForChainRun } from '@langchain/core/callbacks/manager';
import { HumanMessage } from '@langchain/core/messages';
import type { BasePromptValueInterface } from '@langchain/core/prompt_values';
import { Runnable, type RunnableConfig } from '@langchain/core/runnables';
import { PangeaConfig, URLIntelService } from 'pangea-node-sdk';

export class MaliciousUrlsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MaliciousUrlsError';
  }
}

const URL_RE =
  /https?:\/\/(?:[-\w.]|%[\da-fA-F]{2})+(?::\d+)?(?:\/[\w./?%&=-]*)?(?<!\.)/;

export class PangeaUrlIntelGuard<
  RunInput extends BasePromptValueInterface,
> extends Runnable<RunInput, RunInput> {
  static lc_name() {
    return 'PangeaUrlIntelGuard';
  }

  lc_namespace = ['pangeacyber', 'runnables'];

  private readonly client;
  private readonly threshold: number;

  constructor(token: string, domain = 'aws.us.pangea.cloud', threshold = 70) {
    super();
    this.client = new URLIntelService(token, new PangeaConfig({ domain }));
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

    // Find all URLs in the text.
    const ipAddresses = text.match(URL_RE);
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
      throw new MaliciousUrlsError(
        'One or more URLs have a malice score above the threshold.'
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
