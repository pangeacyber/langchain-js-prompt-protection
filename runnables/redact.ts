import type { CallbackManagerForChainRun } from '@langchain/core/callbacks/manager';
import { HumanMessage } from '@langchain/core/messages';
import type { BasePromptValueInterface } from '@langchain/core/prompt_values';
import { Runnable, type RunnableConfig } from '@langchain/core/runnables';
import { PangeaConfig, RedactService } from 'pangea-node-sdk';

export class PangeaRedactRunnable<
  RunInput extends BasePromptValueInterface,
> extends Runnable<RunInput, RunInput> {
  static lc_name() {
    // biome-ignore lint/nursery/noSecrets: false positive.
    return 'PangeaRedactRunnable';
  }

  lc_namespace = ['pangeacyber', 'runnables'];

  private client;

  constructor(token: string, domain = 'aws.us.pangea.cloud') {
    super();
    this.client = new RedactService(token, new PangeaConfig({ domain }));
  }

  async _invoke(
    input: RunInput,
    _config?: Partial<RunnableConfig>,
    _runManager?: CallbackManagerForChainRun
  ): Promise<RunInput> {
    const messages = input.toChatMessages();
    const humanMessages = messages.filter((m) => m instanceof HumanMessage);
    const latestHumanMessage = humanMessages.pop();
    if (!latestHumanMessage) {
      return input;
    }

    const text = latestHumanMessage.content as string;
    if (!text) {
      return input;
    }

    // Redact any sensitive text.
    const redacted = await this.client.redact(text);
    if (!redacted.result) {
      throw new Error('Failed to redact text.');
    }

    if (redacted.result.redacted_text) {
      latestHumanMessage.content = redacted.result.redacted_text;
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
