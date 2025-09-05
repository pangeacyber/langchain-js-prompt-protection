import type { CallbackManagerForChainRun } from '@langchain/core/callbacks/manager';
import { HumanMessage } from '@langchain/core/messages';
import type { BasePromptValueInterface } from '@langchain/core/prompt_values';
import { Runnable, type RunnableConfig } from '@langchain/core/runnables';
import { AuditService, PangeaConfig } from 'pangea-node-sdk';

export class PangeaAuditRunnable<
  RunInput extends BasePromptValueInterface,
> extends Runnable<RunInput, RunInput> {
  static lc_name() {
    return 'PangeaAuditRunnable';
  }

  lc_namespace = ['pangeacyber', 'runnables'];

  private readonly client;

  constructor(
    token: string,
    configId?: string,
    domain = 'aws.us.pangea.cloud'
  ) {
    super();

    this.client = new AuditService(
      token,
      new PangeaConfig({ domain }),
      undefined,
      configId
    );
  }

  async _invoke(
    input: RunInput,
    _config?: Partial<RunnableConfig>,
    _runManager?: CallbackManagerForChainRun
  ): Promise<RunInput> {
    const messages = input.toChatMessages();
    const humanMessages = messages.filter((m) => m instanceof HumanMessage);
    const text = humanMessages.pop()?.content;
    if (!text) {
      return input;
    }

    await this.client.logBulk([
      {
        event_type: 'inference:user_prompt',
        event_input: text,
      },
    ]);

    return input;
  }

  override invoke(
    input: RunInput,
    config: Partial<RunnableConfig> = {}
  ): Promise<RunInput> {
    return this._callWithConfig(this._invoke, input, config);
  }
}
